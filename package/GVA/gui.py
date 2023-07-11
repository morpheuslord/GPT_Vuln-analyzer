import json
import re
from typing import Any
from typing import Optional

import customtkinter
import dns.resolver
import nmap
import openai
import requests
from rich.progress import track

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

root = customtkinter.CTk()
root.title("GVA - GUI")
root.geometry("600x400")

nm = nmap.PortScanner()
model_engine = "text-davinci-003"


def application() -> None:
    try:
        apikey = entry1.get()
        openai.api_key = apikey
        target = entry2.get()
        attack = entry5.get()
        outputf = str(entry4.get())
        match attack:
            case 'geo':
                val = geoip(apikey, target)
                print(val)
                output_save(val, outputf)
            case "nmap":
                p = int(entry3.get())
                match p:
                    case 1:
                        val = scanner(target, 1, apikey)
                        print(val)
                        output_save(val, outputf)
                    case 2:
                        val = scanner(target, 2, apikey)
                        print(val)
                        output_save(val, outputf)
                    case 3:
                        val = scanner(target, 3, apikey)
                        print(val)
                        output_save(val, outputf)
                    case 4:
                        val = scanner(target, 4, apikey)
                        print(val)
                        output_save(val, outputf)
                    case 5:
                        val = scanner(target, 5, apikey)
                        print(val)
                        output_save(val, outputf)
            case "dns":
                val = dns_recon(target, apikey)
                output_save(val, outputf)
            case "subd":
                val = sub(target)
                output_save(val, outputf)
    except KeyboardInterrupt:
        print("Keyboard Interrupt detected ...")


def dns_extract_data(json_string: str) -> Any:
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


def port_extract_data(json_string: str) -> Any:
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


def DnsAI(analyze: str, key: Optional[str]) -> str:
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
        return dns_extract_data(str(response))
    except KeyboardInterrupt:
        print("Bye")
        quit()


def PortAI(key: str, data: Any) -> str:
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
        return port_extract_data(str(response))
    except KeyboardInterrupt:
        print("Bye")
        quit()


def geoip(key: Optional[str], target: str) -> Any:
    if key is None:
        raise ValueError("KeyNotFound: Key Not Provided")
    assert key is not None  # This will help the type checker
    if target is None:
        raise ValueError("InvalidTarget: Target Not Provided")
    url = f"https://api.ipgeolocation.io/ipgeo?apiKey={key}&ip={target}"
    response = requests.get(url)
    content = response.text
    return content


def output_save(output: Any, outf: Any) -> Any:
    top = customtkinter.CTkToplevel(root)
    top.title("GVA Output")
    top.grid_rowconfigure(0, weight=1)
    top.grid_columnconfigure(0, weight=1)
    top.textbox = customtkinter.CTkTextbox(
        master=top, height=500, width=400, corner_radius=0)
    top.textbox.grid(row=0, column=0, sticky="nsew")

    try:
        file = open(outf, 'x')
    except FileExistsError:
        file = open(outf, "r+")
    file.write(str(output))
    file.close
    top.textbox.insert("0.0", text=output)


def sub(target: str) -> Any:
    s_array = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'hod', 'butterfly', 'ckp',
               'tele2', 'receiver', 'reality', 'panopto', 't7', 'thot', 'wien', 'uat-online', 'Footer']

    ss = []
    out = ""
    for subd in s_array:
        try:
            ip_value = dns.resolver.resolve(f'{subd}.{target}', 'A')
            if ip_value:
                ss.append(f'{subd}.{target}')
                if f"{subd}.{target}" in ss:
                    print(f'{subd}.{target} | Found')
                    out += f'{subd}.{target}'
                    out += "\n"
                    out += ""
                else:
                    pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except KeyboardInterrupt:
            print('Ended')
            quit()
    return out


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
        response = DnsAI(key, analyze)
        return str(response)
    except KeyboardInterrupt:
        print("Bye")
        quit()


def scanner(ip: Optional[str], profile: int, key: str) -> str:
    if key is not None:
        pass
    else:
        raise ValueError("KeyNotFound: Key Not Provided")
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
        profile_argument = '-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln'
    else:
        raise ValueError(f"Invalid Argument: {profile}")
    # The scanner with GPT Implemented
    nm.scan('{}'.format(ip), arguments='{}'.format(profile_argument))
    json_data = nm.analyse_nmap_xml_scan()
    analyze = json_data["scan"]
    try:
        response = PortAI(key, analyze)
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return str(response)


frame = customtkinter.CTkFrame(master=root)
frame.pack(pady=20, padx=60, fill="both", expand=True)

label = customtkinter.CTkLabel(
    master=frame, text="GVA System")
label.pack(pady=12, padx=10)

entry1 = customtkinter.CTkEntry(master=frame, placeholder_text="API_KEY")
entry1.pack(pady=12, padx=10)
entry2 = customtkinter.CTkEntry(master=frame, placeholder_text="Target")
entry2.pack(pady=12, padx=10)
entry5 = customtkinter.CTkEntry(
    master=frame, placeholder_text="Attack (nmap/dns)")
entry5.pack(pady=12, padx=10)
entry4 = customtkinter.CTkEntry(master=frame, placeholder_text="Savefile.json")
entry4.pack(pady=12, padx=10)
entry3 = customtkinter.CTkEntry(
    master=frame, placeholder_text="Profile (Only Nmap)")
entry3.pack(pady=12, padx=10)
radiobutton_var = customtkinter.IntVar(value=1)
button = customtkinter.CTkButton(
    master=frame, text="Run", command=application)
button.pack(pady=12, padx=10)

root.mainloop()
