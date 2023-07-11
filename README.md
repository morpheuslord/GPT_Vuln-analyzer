# GPT_Vuln-analyzer

This is a Proof Of Concept application that demostrates how AI can be used to generate accurate results for vulnerability analysis and also allows further utilization of the already super useful ChatGPT made using openai-api, python-nmap, dnsresolver python modules and also use customtkinter and tkinter for the GUI version of the code. This project also has a CLI and a GUI interface, It is capable of doing network vulnerability analysis, DNS enumeration and also subdomain enumeration.

## Requirements

- Python 3.10
- All the packages mentioned in the requirements.txt file
- OpenAI api
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
# domain(target: str, domain_list: List[str)
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

# Specify target for Subdomain Enumeration no profile needed
python gpt_vuln.py --target <HOSTNAME> --attack sub

# Specify target for geolocation lookup
python gpt_vuln.py --target <IP> --attack geo
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
def scanner(ip: str, profile: int) -> str:
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
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analyze)
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
    print(response)
    return 'Done'
```

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

```json
{
  "ip": "█████████████",
  "continent_code": "AS",
  "continent_name": "Asia",
  "country_code2": "IN",
  "country_code3": "IND",
  "country_name": "India",
  "country_capital": "New Delhi",
  "state_prov": "Maharashtra",
  "district": "",
  "city": "Navi Mumbai",
  "zipcode": "400701",
  "latitude": "19.12418",
  "longitude": "73.00551",
  "is_eu": false,
  "calling_code": "+91",
  "country_tld": ".in",
  "languages": "en-IN,hi,bn,te,mr,ta,ur,gu,kn,ml,or,pa,as,bh,sat,ks,ne,sd,kok,doi,mni,sit,sa,fr,lus,inc",
  "country_flag": "https://ipgeolocation.io/static/flags/in_64.png",
  "geoname_id": "10128846",
  "isp": "Reliance Jio Infocomm Limited",
  "connection_type": "",
  "organization": "Reliance Jio Infocomm Limited",
  "currency": {
    "code": "INR",
    "name": "Indian Rupee",
    "symbol": "₹"
  },
  "time_zone": {
    "name": "Asia/Kolkata",
    "offset": 5.5,
    "current_time": "2023-04-07 15:17:57.031+0530",
    "current_time_unix": 1680860877.031,
    "is_dst": false,
    "dst_savings": 0
  }
}
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
