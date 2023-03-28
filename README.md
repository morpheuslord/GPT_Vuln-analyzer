# GPT_Vuln-analyzer

This is a Proof Of Concept application that demostrates how AI can be used to generate accurate results for vulnerability analysis and also allows further utilization of the already super useful ChatGPT.

## Requirements
- Python 3.10
- All the packages mentioned in the requirements.txt file
- OpenAi api

## Usage

- First Change the "__API__KEY__" part of the code with OpenAI api key
```python
openai.api_key = "__API__KEY" # Enter your API key
```
- second install the packages
```bash
pip3 install -r requirements.txt
or
pip install -r requirements.txt
```
- run the code python3 gpt_vuln.py <<Target>> or if windows run python gpt_vuln.py <<Target>>

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

```json
{
    "vulnerabilities": [
        {
            "name": "Port 135 Open",
            "type": "network",
            "severity": "low",
            "description": "TCP port 135 is open, which suggests that Microsoft Windows RPC might be running on this system and could potentially be vulnerable to exploitation."
        },
        {
            "name": "Port 445 Open",
            "type": "network",
            "severity": "low",
            "description": "TCP port 445 is open, which suggests that Microsoft Windows File Share might be running on this system and could potentially be vulnerable to exploitation."
        },
        {
            "name": "Port 902 Open",
            "type": "network",
            "severity": "low",
            "description": "TCP port 902 is open, which suggests that VMware Authentication Daemon might be running on this system and could potentially be vulnerable to exploitation."
        },
        {
            "name": "Port 912 Open",
            "type": "network",
            "severity": "low",
            "description": "TCP port 912 is open, which suggests that VMware Authentication Daemon might be running on this system and could potentially be vulnerable to exploitation."
        },
        {
            "name": "Port 20000 Open",
            "type": "network",
            "severity": "low",
            "description": "TCP port 20000 is open, which suggests that the system could potentially be vulnerable to exploitation."
        },
        {
            "name": "Clock Skew Detected",
            "type": "system",
            "severity": "low",
            "description": "A clock skew of -1 second has been detected, which may indicate an incorrect system configuration or an attack on the system clock."
        },
        {
            "name": "Outdated OS Version Detected",
            "type": "system",
            "severity": "medium",
            "description": "Microsoft Windows 10 Version 1607 is detected, which is no longer supported and is known to contain vulnerabilities."
        }
    ]
}
```

## Advantages

- Can be used in developing a more advanced systems completly made of the API and scanner combination
- Can increase the effectiveness of the final system
- Highly productive when working with models such as GPT3
