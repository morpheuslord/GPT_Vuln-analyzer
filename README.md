# GPT_Vuln-analyzer

This is a Proof Of Concept application that demostrates how AI can be used to generate accurate results for vulnerability analysis and also allows further utilization of the already super useful ChatGPT made using openai-api, python-nmap, dnsresolver python modules and also use customtkinter and tkinter for the GUI version of the code. This project also has a CLI and a GUI interface, It is capable of doing network vulnerability analysis, DNS enumeration and also subdomain enumeration.

## Requirements

- Python 3.10
- All the packages mentioned in the requirements.txt file
- OpenAI API
- IPGeolocation API

## Usage Package

### Import packages

```bash
cd package && pip3/pip install .
```

Simple import any of the 3 packages and then add define the variables accordingly

```python
from GVA import scanner
from GVA import dns_recon
from GVA import subdomain
from GVA import geo
from GVA import gui
from dotenv import load_dotenv()

load_dotenv()
openai_key = os.getenv('OPENAI_API_KEY')
geoIP_key = os.getenv('GEOIP_API_KEY')

sub_domain_list = ['admin', 'whateveryouwant']

# scanner(target: str, profile: int, api_key: str)
# dns_recon(target: str, api_key: str)
# domain(target: str, domain_list: List[str])
# geo(api_key: str, target: str)

print(scanner.scanner('127.0.0.1', 1, openai_key))
print(dns_recon.dns_recon('127.0.0.1', openai_key))
print(subdomain.domain('127.0.0.1', sub_domain_list))
print(geo.geo(geoIP_key, '127.0.0.1'))
gui.application()
```

## Usage CLI

- First Change the "**API**KEY\_\_" part of the code with OpenAI api key and the IPGeolocation API key in the `.env` file

```python
GEOIP_API_KEY = ''
OPENAI_API_KEY = ''
```

- second install the packages

```bash
pip3 install -r requirements.txt
or
pip install -r requirements.txt
```

- run the code python3 gpt_vuln.py

```bash
# Regular Help Menu
python gpt_vuln.py --help

# Rich Help Menu
python gpt_vuln.py --r help

# Specify target with the attack
python gpt_vuln.py --target <IP> --attack dns/nmap

# Specify target and profile for nmap
python gpt_vuln.py --target <IP> --attack nmap --profile <1-5>
(Default:1)

# Specify target for DNS no profile needed
python gpt_vuln.py --target <IP or HOSTNAME> --attack dns

# Specify target for Subdomain Enumeration no profile used default list file
python gpt_vuln.py --target <HOSTNAME> --attack sub

# Specify target for Subdomain Enumeration no profile used custom list file
python gpt_vuln.py --target <HOSTNAME> --attack sub --list <PATH to FILE>

# Specify target for geolocation lookup
python gpt_vuln.py --target <IP> --attack geo

# Interactive step by step cli interface
python gpt_vuln.py --menu True
```
#### CLI Interface Option

```bash
  ________________________
| GVA Usage in progress... |
  ========================
                        \
                         \
                           ^__^
                           (oo)\_______
                           (__)\       )\/\
                               ||----w |
                               ||     ||
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Options ┃ Utility        ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ 1       │ Nmap Enum      │
│ 2       │ DNS Enum       │
│ 3       │ Subdomain Enum │
│ 4       │ GEO-IP Enum    │
│ q       │ Quit           │
└─────────┴────────────────┘
Enter your choice:
```

Supported in both windows and linux

## Understanding the code

Profiles:

| Parameter | Return data | Description           | Nmap Command                                          |
| :-------- | :---------- | :-------------------- | :---------------------------------------------------- |
| `p1`      | `json`      | Effective Scan        | `-Pn -sV -T4 -O -F`                                   |
| `p2`      | `json`      | Simple Scan           | `-Pn -T4 -A -v`                                       |
| `p3`      | `json`      | Low Power Scan        | `-Pn -sS -sU -T4 -A -v`                               |
| `p4`      | `json`      | Partial Intense Scan  | `-Pn -p- -T4 -A -v`                                   |
| `p5`      | `json`      | Complete Intense Scan | `-Pn -sS -sU -T4 -A -PE -PP  -PY -g 53 --script=vuln` |

The profile is the type of scan that will be executed by the nmap subprocess. The Ip or target will be provided via argparse. At first the custom nmap scan is run which has all the curcial arguments for the scan to continue. Next, the scan data is extracted from the huge pile of data driven by nmap. the "scan" object has a list of sub-data under "tcp" each labled according to the ports opened. once the data is extracted the data is sent to openai API davenci model via a prompt. the prompt specifically asks for a JSON output and the data also to be used in a certain manner.

The entire structure of request that has to be sent to the openai API is designed in the completion section of the Program.

```python
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

```

# Regex

We use Regex to extract only the important information from the custom prompt provided this reduces the total amount of unwanted
data

```python
def extract_data(json_string):
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
```

The AI code defines an output format and commands the AI to follow a few pre dertermined rules to increase accuracy.

The regex extraction code does the extraction and further the main function arranges them into tables.

### Output

nmap output:

```table
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Elements           ┃ Results                                             ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ critical score     │ High                                                │
│ os information     │ Microsoft Windows 11 21H2                           │
│ open ports         │ 80, 22, 445, 902, 912                               │
│ open services      │ http, ssh, microsoft-ds, vmware-auth, vmware-auth   │
│ vulnerable service │ OpenSSH                                             │
│ found cve          │ CVE-2023-28531                                      │
└────────────────────┴─────────────────────────────────────────────────────┘
```

DNS Output:
target is jainuniversity.ac.in

```table
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Elements ┃ Results                                                                                                           ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ A        │ 172.67.147.95", "104.21.41.132                                                                                    │
│ AAA      │                                                                                                                   │
│ NS       │ mia.ns.cloudflare.com.","paul.ns.cloudflare.com.                                                                  │
│ MX       │ 30 aspmx5.googlemail.com.","30 aspmx4.googlemail.com.","20 alt2.aspmx.l.google.com.","30                          │
│          │ aspmx3.googlemail.com.","30 aspmx2.googlemail.com.","20 alt1.aspmx.l.google.com.","10 aspmx.l.google.com.         │
│ PTR      │                                                                                                                   │
│ SOA      │ mia.ns.cloudflare.com. dns.cloudflare.com. 2309618668 10000 2400 604800 3600                                      │
│ TXT      │ atlassian-sending-domain-verification=5b358ce4-5ad3-404d-b4b4-005bf933603b","include:_spf.atlassian.net           │
└──────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

GEO Location output:

```table
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Identifiers                 ┃ Data                                                                    ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ ip                          │ █████████████                                                           │
│ continent_code              │ AS                                                                      │
│ continent_name              │ Asia                                                                    │
│ country_code2               │ IN                                                                      │
│ country_code3               │ IND                                                                     │
│ country_name                │ India                                                                   │
│ country_capital             │ New Delhi                                                               │
│ state_prov                  │ Haryana                                                                 │
│ state_code                  │ IN-HR                                                                   │
│ district                    │                                                                         │
│ city                        │ Gurugram                                                                │
│ zipcode                     │ 122003                                                                  │
│ latitude                    │ 28.44324                                                                │
│ longitude                   │ 77.05501                                                                │
│ is_eu                       │ False                                                                   │
│ calling_code                │ +91                                                                     │
│ country_tld                 │ .in                                                                     │
│ languages                   │ en-IN,hi,bn,te,mr,ta,ur,gu,kn,ml,or,pa,as,bh,sat,ks,ne,sd,kok,doi,mni,… │
│ country_flag                │ https://ipgeolocation.io/static/flags/in_64.png                         │
│ geoname_id                  │ 9148991                                                                 │
│ isp                         │ Bharti Airtel Limited                                                   │
│ connection_type             │                                                                         │
│ organization                │ Bharti Airtel Limited                                                   │
│ currency.code               │ INR                                                                     │
│ currency.name               │ Indian Rupee                                                            │
│ currency.symbol             │ ₹                                                                       │
│ time_zone.name              │ Asia/Kolkata                                                            │
│ time_zone.offset            │ 5.5                                                                     │
│ time_zone.current_time      │ 2023-07-11 17:08:35.057+0530                                            │
│ time_zone.current_time_unix │ 1689075515.057                                                          │
│ time_zone.is_dst            │ False                                                                   │
│ time_zone.dst_savings       │ 0                                                                       │
└─────────────────────────────┴─────────────────────────────────────────────────────────────────────────┘
```

# Usage GUI

The GUI uses customtkinter for the running of the code. The interface is straight forward the only thing required to remember is:

- When using dns attack dont specify the profile

```bash
python GVA_gui.py
```

### main window

![main](https://user-images.githubusercontent.com/70637311/228863455-993e0a21-c06c-44c7-87e6-68d758a78e2c.jpeg)

### output_DNS

![dns_output](https://user-images.githubusercontent.com/70637311/228863540-553f8560-fdf5-48f7-96e8-1f831ab3a8f2.png)

### output_nmap

![nmap_output](https://user-images.githubusercontent.com/70637311/228863611-5d8380f0-28d5-4925-9ad3-62cd28a1ecd4.png)

### oytput_geo

![GEO_output](https://user-images.githubusercontent.com/70637311/230589239-b11c39df-b047-4fbb-bb68-61d30fe2b3c9.png)

## Advantage

- Can be used in developing a more advanced systems completly made of the API and scanner combination
- Has the capability to analize DNS information and reslove Mustiple records it a more better format.
- Can increase the effectiveness of the final system
- Can also perform subdomain enumeration
- Highly productive when working with models such as GPT3
