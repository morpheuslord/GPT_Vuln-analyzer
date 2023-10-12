import json
import re
from typing import Any
from typing import Optional
import openai
import requests
model_engine = "gpt-3.5-turbo-0613"


class DNS_AI_MODEL():
    @staticmethod
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
            data = dns_ai_data_regex(str(generated_text))
            print(data)
            return dns_ai_data_regex(str(generated_text))
        else:
            print("Error: Unable to generate text. Status Code:", response.status_code)
            return "None"

    @staticmethod
    def llama_AI(self, data: str, mode: str, lkey, lendpoint):
        api_url = 'http://localhost:5000/api/chatbot'

        user_instruction = """
            Do a DNS scan analysis on the provided DNS scan information. The DNS output must return in a asked format accorging to the provided output format. The data must be accurate in regards towards a pentest report.
            The data must follow the following rules:
            1) The DNS scans must be done from a pentester point of view
            2) The final output must be minimal according to the format given
            3) The final output must be kept to a minimal
            4) So the analysis and provide your view according to the given format
            5) Remember to provide views as a security engineer or an security analyst.
            The output format:
            "A":
            - List the A records and security views on them
            "AAA":
            - List the AAA records and security views on them
            "NS":
            - List the NS records and security views on them
            "MX":
            - List the MX records and security views on them
            "PTR":
            - List the PTR records and security views on them
            "SOA":
            - List the SOA records and security views on them
            "TXT":
            - List the TXT records and security views on them
        """
        user_message = f"""
            DNS Data to be analyzed: {data}
        """

        model_name = "TheBloke/Llama-2-7B-Chat-GGML"
        file_name = "llama-2-7b-chat.ggmlv3.q4_K_M.bin"
        if mode == "local":
            bot_response = self.chat_with_api(api_url, user_message, user_instruction, model_name, file_name)
        elif mode == "runpod":
            prompt = f"[INST] <<SYS>> {user_instruction}<</SYS>> NMAP Data to be analyzed: {user_message} [/INST]"
            bot_response = self.llama_runpod_api(prompt, lkey, lendpoint)
        bot_response = self.chat_with_api(api_url, user_message, user_instruction, model_name, file_name)
        print("test")
        if bot_response:
            return bot_response

    @staticmethod
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
            messages = [{"content": prompt, "role": "user"}]
            # A structure for the request
            response = openai.ChatCompletion.create(
                model=model_engine,
                messages=messages,
                max_tokens=1024,
                n=1,
                stop=None,
            )
            response = response['choices'][0]['message']['content']
            return dns_ai_data_regex(str(response))
        except KeyboardInterrupt:
            print("Bye")
            quit()


class NMAP_AI_MODEL():
    @staticmethod
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
            return nmap_ai_data_regex(str(generated_text))
        else:
            print("Error: Unable to generate text. Status Code:", response.status_code)
            return "None"

    @staticmethod
    def Llama_AI(data: str, mode: str, lkey: str, lendpoint: str) -> Any:
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
        if mode == "local":
            bot_response = chat_with_api(api_url, user_message, user_instruction, model_name, file_name)
        elif mode == "runpod":
            prompt = f"[INST] <<SYS>> {user_instruction}<</SYS>> NMAP Data to be analyzed: {user_message} [/INST]"
            bot_response = llama_runpod_api(prompt, lkey, lendpoint)
        if bot_response:
            return bot_response

    @staticmethod
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
            messages = [{"content": prompt, "role": "assistant"}]
            # A structure for the request
            response = openai.ChatCompletion.create(
                model=model_engine,
                messages=messages,
                max_tokens=2500,
                n=1,
                stop=None,
            )
            response = response['choices'][0]['message']['content']
            rsp = str(response)
            return str(nmap_ai_data_regex(rsp))
        except KeyboardInterrupt:
            print("Bye")
            quit()


class JWT_AI_MODEL():
    @staticmethod
    def BardAI(key: str, jwt_data: Any) -> str:
        prompt = f"""
        Perform a comprehensive analysis on the provided JWT token. The analysis output must be in a JSON format according to the provided output structure. Ensure accuracy for inclusion in a penetration testing report.
        Follow these guidelines:
        1) Analyze the JWT token from a pentester's perspective
        2) Keep the final output minimal while adhering to the given format
        3) Highlight JWT-specific details and enumerate possible attacks and vulnerabilities
        5) For the output "Algorithm Used" value use the Algorithm value from the JWT data.
        6) For the output "Header" value use the Header value from the JWT data.
        7) For the "Payload" Use the decoded payloads as a reference and then analyze any attack endpoints.
        8) For "Signature" mention the signatures discovered.
        9) List a few endpoints you feel are vulnerable for "VulnerableEndpoints"

        The output format:
        {{
            "Algorithm Used": "",
            "Header": "",
            "Payload": "",
            "Signature": "",
            "PossibleAttacks": "",
            "VulnerableEndpoints": ""
        }}

        JWT Token Data to be analyzed: {jwt_data}
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
            jwt_analysis_data = jwt_ai_data_regex(str(generated_text))
            print(jwt_analysis_data)
            return jwt_analysis_data
        else:
            print("Error: Unable to generate text. Status Code:", response.status_code)
            return "None"

    @staticmethod
    def llama_AI(self, jwt_data: str, mode: str, lkey, lendpoint):
        api_url = 'http://localhost:5000/api/chatbot'

        user_instruction = """
            Perform a comprehensive analysis on the provided JWT token. The JWT analysis output must be in a asked format according to the provided output structure. Ensure accuracy for inclusion in a penetration testing report.
            Follow these guidelines:
            1) Analyze the JWT token from a pentester's perspective
            2) Keep the final output minimal while adhering to the given format
            3) Highlight JWT-specific details and enumerate possible attacks

            The output format:
            "Header":
            - List the JWT header details and security views on them
            "Payload":
            - List the JWT payload details and security views on them
            "Signature":
            - Provide insights on the JWT signature
            "PossibleAttacks":
            - List possible JWT exploits and attacks
        """
        user_message = f"""
            JWT Token Data to be analyzed: {jwt_data}
        """

        model_name = "TheBloke/Llama-2-7B-Chat-GGML"
        file_name = "llama-2-7b-chat.ggmlv3.q4_K_M.bin"
        if mode == "local":
            bot_response = self.chat_with_api(api_url, user_message, user_instruction, model_name, file_name)
        elif mode == "runpod":
            prompt = f"[INST] <<SYS>> {user_instruction}<</SYS>> JWT Token Data to be analyzed: {user_message} [/INST]"
            bot_response = self.llama_runpod_api(prompt, lkey, lendpoint)
        bot_response = self.chat_with_api(api_url, user_message, user_instruction, model_name, file_name)
        print("test")
        if bot_response:
            return bot_response

    @staticmethod
    def gpt_ai(analyze: str, api_key: Optional[str]) -> str:
        openai.api_key = api_key
        prompt = f"""
        Perform a comprehensive analysis on the provided JWT token. The analysis output must be in a JSON format according to the provided output structure. Ensure accuracy for inclusion in a penetration testing report.
        Follow these guidelines:
        1) Analyze the JWT token from a pentester's perspective
        2) Keep the final output minimal while adhering to the given format
        3) Highlight JWT-specific details and enumerate possible attacks and vulnerabilities
        5) For the output "Algorithm Used" value use the Algorithm value from the JWT data.
        6) For the output "Header" value use the Header value from the JWT data.
        7) For the "Payload" Use the decoded payloads as a reference and then analyze any attack endpoints.
        8) For "Signature" mention the signatures discovered.
        9) List a few endpoints you feel are vulnerable for "VulnerableEndpoints"

        The output format:
        {{
            "Algorithm Used": "",
            "Header": "",
            "Payload": "",
            "Signature": "",
            "PossibleAttacks": "",
            "VulnerableEndpoints": ""
        }}

        JWT Token Data to be analyzed: {analyze}
        """
        try:
            messages = [{"content": prompt, "role": "user"}]
            response = openai.ChatCompletion.create(
                model=model_engine,
                messages=messages,
                max_tokens=1024,
                n=1,
                stop=None,
            )
            response = response['choices'][0]['message']['content']
            rsp = str(response)
            return rsp
        except KeyboardInterrupt:
            print("Bye")
            quit()


def chat_with_api(api_url: str, user_message: str, user_instruction: str, model_name: str, file_name: str = None) -> Any:
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


def llama_runpod_api(prompt: str, lkey: str, lendpoint: str) -> Any:
    url = f"https://api.runpod.ai/v2/{lendpoint}/runsync"
    payload = json.dumps({
        "input": {
            "prompt": prompt,
            "max_new_tokens": 4500,
            "temperature": 0.9,
            "top_k": 50,
            "top_p": 0.7,
            "repetition_penalty": 1.2,
            "batch_size": 8,
            "stop": [
                "</s>"
            ]
        }
    })
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {lkey}',
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    response_t = json.loads(response.text)
    return response_t["output"]


def dns_ai_data_regex(json_string: str) -> Any:
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


def nmap_ai_data_regex(json_string: str) -> Any:
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


def jwt_ai_data_regex(json_string: str) -> Any:
    # Define the regular expression patterns for individual values
    header_pattern = r'"Header": \{\s*"alg": "(.*?)",\s*"typ": "(.*?)"\s*\}'
    payload_pattern = r'"Payload": \{\s*"iss": "(.*?)",\s*"sub": "(.*?)",\s*"aud": "(.*?)",\s*"exp": "(.*?)",\s*"nbf": "(.*?)",\s*"iat": "(.*?)"\s*\}'
    signature_pattern = r'"Signature": "(.*?)"'
    possible_attacks_pattern = r'"PossibleAttacks": "(.*?)"'
    vulnerable_endpoints_pattern = r'"VulnerableEndpoints": "(.*?)"'

    # Initialize variables for extracted data
    header = {}
    payload = {}
    signature = ""
    possible_attacks = ""
    vulnerable_endpoints = ""

    # Extract individual values using patterns
    match_header = re.search(header_pattern, json_string)
    if match_header:
        header = {"alg": match_header.group(1), "typ": match_header.group(2)}

    match_payload = re.search(payload_pattern, json_string)
    if match_payload:
        payload = {
            "iss": match_payload.group(1),
            "sub": match_payload.group(2),
            "aud": match_payload.group(3),
            "exp": match_payload.group(4),
            "nbf": match_payload.group(5),
            "iat": match_payload.group(6)
        }

    match_signature = re.search(signature_pattern, json_string)
    if match_signature:
        signature = match_signature.group(1)

    match_attacks = re.search(possible_attacks_pattern, json_string)
    if match_attacks:
        possible_attacks = match_attacks.group(1)

    match_endpoints = re.search(vulnerable_endpoints_pattern, json_string)
    if match_endpoints:
        vulnerable_endpoints = match_endpoints.group(1)

    # Create a dictionary to store the extracted data
    data = {
        "Header": header,
        "Payload": payload,
        "Signature": signature,
        "PossibleAttacks": possible_attacks,
        "VulnerableEndpoints": vulnerable_endpoints
    }

    # Convert the dictionary to JSON format
    json_output = json.dumps(data)

    return json_output
