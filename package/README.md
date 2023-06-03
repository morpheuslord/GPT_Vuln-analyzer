# GPT_Vuln-analyzer

This is a Proof Of Concept application that demostrates how AI can be used to generate accurate results for vulnerability analysis and also allows further utilization of the already super useful ChatGPT made using openai-api, python-nmap, dnsresolver python modules and also use customtkinter and tkinter for the GUI version of the code. This project also has a CLI and a GUI interface, It is capable of doing network vulnerability analysis, DNS enumeration and also subdomain enumeration.

## Requirements
- Python 3.10
- All the packages mentioned in the requirements.txt file
- OpenAi api

## Usage Package

### Import packages 
`pip install GVA`
or
`pip3 install GVA`

Simple import any of the 3 packages and then add define the variables accordingly
```python
from GVA import profile
from GVA import dns
from GVA import subdomain

key = "__API__KEY__"
profile.openai.api_key = key
dns.openai.api_key = key

print(profile.p1("<IP>"))
print(dns.dnsr("<DOMAIN>"))
subdomain.sub("<DOMAIN>")
```

## Usage CLI

- First Change the "__API__KEY__" part of the code with OpenAI api key
```python
akey = "__API__KEY__" # Enter your API key
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
python get_vuln.py --r help

# Specify target with the attack 
python gpt_vuln.py --target <IP> --attack dns/nmap

# Specify target and profile for nmap
python get_vuln.py --target <IP> --attack nmap --profile <1-5> 
(Default:1)

# Specify target for DNS no profile needed
python get_vuln.py --target <IP or HOSTNAME> --attack dns

# Specify target for Subdomain Enumeration no profile needed
python get_vuln.py --target <HOSTNAME> --attack sub
```

Supported in both windows and linux
    
## Understanding the code

Profiles:

| Parameter | Return data     | Description | Nmap Command |
| :-------- | :------- | :-------------------------------- | :---------|
| `p1`      | `json` | Effective  Scan | `-Pn -sV -T4 -O -F`|
| `p2`      | `json` | Simple  Scan | `-Pn -T4 -A -v`|
| `p3`      | `json` | Low Power  Scan | `-Pn -sS -sU -T4 -A -v`|
| `p4`      | `json` | Partial Intense  Scan | `-Pn -p- -T4 -A -v`|
| `p5`      | `json` | Complete Intense  Scan | `-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln`|

The profile is the type of scan that will be executed by the nmap subprocess. The Ip or target will be provided via argparse. At first the custom nmap scan is run which has all the curcial arguments for the scan to continue. nextly the scan data is extracted from the huge pile of data which has been driven by nmap. the "scan" object has a list of sub data under "tcp" each labled according to the ports opened. once the data is extracted the data is sent to openai API davenci model via a prompt. the prompt specifically asks for an JSON output and the data also to be used in a certain manner. 

The entire structure of request that has to be sent to the openai API is designed in the completion section of the Program.
```python
def profile(ip):
    nm.scan('{}'.format(ip), arguments='-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln')
    json_data = nm.analyse_nmap_xml_scan()
    analize = json_data["scan"]
    # Prompt about what the quary is all about
    prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(analize)
    # A structure for the request
    completion = openai.Completion.create(
        engine=model_engine,
        prompt=prompt,
        max_tokens=1024,
        n=1,
        stop=None,
    )
    response = completion.choices[0].text
    return response
```
### Output
nmap output:
```json
{
    "Vulnerability Report": {
        "Target IP": "127.0.0.1",
        "OS Detected": {
            "Name": "Microsoft Windows 10 1607",
            "Accuracy": "100",
            "CPE": [
                "cpe:/o:microsoft:windows_10:1607"
            ]
        },
        "Open Ports": {
            "Port 135": {
                "State": "open",
                "Reason": "syn-ack",
                "Name": "msrpc",
                "Product": "Microsoft Windows RPC",
                "Version": "",
                "Extra Info": "",
                "Conf": "10",
                "CPE": "cpe:/o:microsoft:windows"
            },
            "Port 445": {
                "State": "open",
                "Reason": "syn-ack",
                "Name": "microsoft-ds",
                "Product": "",
                "Version": "",
                "Extra Info": "",
                "Conf": "3",
                "CPE": ""
            }
        },
        "Vulnerabilities": {
            "Port 135": [],
            "Port 445": []
        }
    }
}
```
DNS Output:
target is google.com
```json

{
  "A" : { 
    "ip": "142.250.195.174",
  },
  "AAAA": { 
    "ip": "2404:6800:4007:826::200e"
  },
  "NS": {
    "nameservers": [
      "ns2.google.com.", 
      "ns1.google.com.",
      "ns3.google.com.",
      "ns4.google.com."
    ]
  },
  "MX" : {
    "smtp": "10 smtp.google.com."
  },
  "SOA" : {
    "nameserver": "ns1.google.com.",
    "admin": "dns-admin.google.com.",
    "serial": "519979037",
    "refresh": "900",
    "retry": "900",
    "expire": "1800",
    "ttl": "60"
  },
  "TXT": {
    "onetrust-domain-verification": "de01ed21f2fa4d8781cbc3ffb89cf4ef",
    "webexdomainverification.8YX6G": "6e6922db-e3e6-4a36-904e-a805c28087fa", 
    "globalsign-smime-dv": "CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8=",
    "google-site-verification": [
      "wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o", 
      "TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ"
    ],
    "docusign": [
      "05958488-4752-4ef2-95eb-aa7ba8a3bd0e", 
      "1b0a6754-49b1-4db5-8540-d2c12664b289"
    ],
    "atlassian-domain-verification":  "5YjTmWmjI92ewqkx2oXmBaD60Td9zWon9r6eakvHX6B77zzkFQto8PQ9QsKnbf4I",
    "v=spf1 include:_spf.google.com ~all": "v=spf1 include:_spf.google.com ~all",
    "facebook-domain-verification": "22rm551cu4k0ab0bxsw536tlds4h95",
    "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB": "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB",
    "apple-domain-verification": "30afIBcvSuDV2PLX"
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

## Advantage

- Can be used in developing a more advanced systems completly made of the API and scanner combination
- Has the capability to analize DNS information and reslove Mustiple records it a more better format.
- Can increase the effectiveness of the final system
- Can also perform subdomain enumeration
- Highly productive when working with models such as GPT3
