# GPT_Vuln-analyzer (GVA)

![License](https://img.shields.io/badge/license-MIT-green) ![Python](https://img.shields.io/badge/python-3.10%2B-blue)

GVA is an AI-assisted reconnaissance and vulnerability-analysis toolkit. It runs the
scan (nmap, DNS, subdomains, JWT, PCAP, GeoIP), then hands the raw output to a large
language model that returns a structured, pentester-oriented analysis. It ships with
both a command-line interface and a desktop GUI.

The AI layer is provider-agnostic: OpenAI, Anthropic Claude, Google Gemini, and local
Ollama models are all supported. Pick one, or run several at once and let a
deliberation agent reconcile their analyses into a single report.

## Features

- **Nmap analysis** — ten curated scan profiles, from a fast unprivileged triage to a
  full-port SYN audit, with the results explained by the AI.
- **DNS recon** — forward, reverse, and zone-transfer lookups, analysed into typed records.
- **Subdomain enumeration** — resolve a wordlist of subdomains against a domain.
- **JWT analysis** — decode a token and surface likely attacks and endpoints to test.
- **PCAP analysis** — inspect a capture for traffic, ARP/MAC spoofing, and cleartext credentials.
- **GeoIP lookup** — geolocate an IP via ipgeolocation.io.
- **Password cracking** — wordlist and brute-force cracking with common hash algorithms.
- **Multi-provider AI** — validated structured output via [Pydantic AI](https://ai.pydantic.dev/),
  with concurrent analysis and a deliberation step across models.

## Requirements

- Python 3.10 or later
- Dependencies from `pyproject.toml` (managed with [uv](https://docs.astral.sh/uv/)) or `requirements.txt`
- An API key for at least one AI provider (OpenAI, Anthropic, or Google Gemini). Ollama runs locally and needs no key.
- `nmap` on `PATH` for the nmap attack
- Wireshark / `tshark` on `PATH` for the pcap attack
- An [ipgeolocation.io](https://ipgeolocation.io/) key for the geo attack
- Docker, only if you use the local Ollama provider

### nmap notes

The nmap attack shells out to the system `nmap` binary through `python-nmap`, so nmap
must be installed and runnable.

- **Profiles 6–10 need root** (SYN/UDP/OS-detection flags). GVA escalates only the nmap
  step with `sudo`, or you can pass `--sudo`. Profiles 1–5 run unprivileged; profile 1
  is the default and works without root.
- **Immutable distros (Bazzite/Silverblue), `libssh2.so.1: cannot open shared object file`:**
  the system nmap is missing a shared library. If you use conda,
  `conda install -c conda-forge nmap` is self-contained and takes PATH precedence.
  Otherwise layer it with `rpm-ostree install libssh2` (then reboot), or use
  `brew install nmap` or a distrobox container.

If nmap is missing or broken, the attack reports a clean error instead of crashing.

## Installation

The install script sets up system packages, uv, and the Python dependencies. Run it as
your normal user; it elevates only the system-package step with sudo.

```bash
./install.sh              # full install
./install.sh --no-system  # skip system packages (uv + Python deps only)
```

It auto-detects your package manager (apt, dnf, pacman, zypper, apk, brew, or
rpm-ostree), installs uv at user level, runs `uv sync`, and creates `.env`. Do not
`sudo su` first: if the project sits on a user-only mount (for example `/run/host` or
`/media`), root cannot read it, so the normal-user invocation is the reliable path.

To install manually with uv:

```bash
uv sync
```

`pip install -r requirements.txt` also works as a fallback.

### Configuration

Copy the example environment file and fill in keys for the providers you want. Any
provider without a key is skipped automatically.

```bash
cp .env.example .env
```

```dotenv
GEOIP_API_KEY=
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GEMINI_API_KEY=
```

## AI providers

Every provider is a Pydantic AI agent that returns a validated, structured result.
Select more than one and each model analyses the scan independently and concurrently;
a deliberation agent (one of the selected models) then reconciles them into a single
consolidated report. A live progress board shows each model's status, timing, and the
deliberation step while it runs.

| Provider  | Key      | Default model      | Approx. price / 1M tokens |
|-----------|----------|--------------------|---------------------------|
| OpenAI    | `openai` | `gpt-5.6-luna`     | $0.20 in / $1.20 out      |
| Anthropic | `claude` | `claude-haiku-4-5` | $1.00 in / $5.00 out      |
| Google    | `gemini` | `gemini-3.6-flash` | $0.75 in / $3.75 out      |
| Ollama    | `ollama` | `llama3`           | local / free              |

Override any model with the matching `*_MODEL` variable in `.env`. See `.env.example`
for alternatives. Ollama uses a local Docker image and is started automatically when
selected.

## Usage (CLI)

Run with `uv run gpt_vuln.py ...`, or `python gpt_vuln.py ...` inside an activated venv.

```bash
# Help
uv run gpt_vuln.py --help
uv run gpt_vuln.py --rich_menu help

# Nmap scan (default profile 1), analysed by OpenAI
python gpt_vuln.py --target scanme.nmap.org --attack nmap --ai openai

# Choose a scan profile (see the profile table below, or --list_profiles)
python gpt_vuln.py --target scanme.nmap.org --attack nmap --profile 2
python gpt_vuln.py --list_profiles

# DNS recon (no profile needed)
python gpt_vuln.py --target example.com --attack dns

# Subdomain enumeration (default or custom wordlist)
python gpt_vuln.py --target example.com --attack sub
python gpt_vuln.py --target example.com --attack sub --sub_list path/to/list.txt

# GeoIP lookup
python gpt_vuln.py --target 8.8.8.8 --attack geo

# JWT analysis
python gpt_vuln.py --target <token> --attack jwt

# PCAP analysis
python gpt_vuln.py --target capture.pcap --attack pcap --output outputs/output.json

# Several providers: each analyses independently, then one consolidated report
python gpt_vuln.py --target example.com --attack dns --ai openai,claude,gemini

# Choose which model deliberates, and also show each model's own analysis
python gpt_vuln.py --target example.com --attack dns --ai all --summarizer claude --show_individual

# Password cracking
python gpt_vuln.py --password_hash <hash> --wordlist_file words.txt --algorithm md5 --parallel

# Interactive step-by-step menu
python gpt_vuln.py --menu
```

### Interactive menu

`--menu` launches a guided interface that prompts for the target, options, and AI
providers for each attack.

```text
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Option  ┃ Action         ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ 1       │ Nmap scan      │
│ 2       │ DNS recon      │
│ 3       │ Subdomain enum │
│ 4       │ GeoIP lookup   │
│ 5       │ JWT analysis   │
│ 6       │ PCAP analysis  │
│ 7       │ Hash cracker   │
│ q       │ Quit           │
└─────────┴────────────────┘
```

## Nmap scan profiles

Profiles 1–5 run unprivileged (TCP connect scans, no root). Profile 1 is the default.
Profiles 6–10 use SYN/UDP/OS-detection flags that need root; GVA escalates just the
nmap step with `sudo` when you pick one. Run `python gpt_vuln.py --list_profiles` to
see this table in your terminal.

| #  | Name          | Root | What it does                                              | Nmap command                                                                                   |
|----|---------------|:----:|----------------------------------------------------------|------------------------------------------------------------------------------------------------|
| 1  | Quick         |  no  | Top 100 TCP ports with service versions (fast triage).   | `-Pn -sT -sV -T4 --top-ports 100`                                                              |
| 2  | Standard      |  no  | Top 1000 ports with versions and default NSE scripts.    | `-Pn -sT -sV -sC -T4 --top-ports 1000`                                                         |
| 3  | Full TCP      |  no  | Every TCP port (1–65535) with versions.                  | `-Pn -sT -sV -p- -T4`                                                                           |
| 4  | Web services  |  no  | HTTP/S-focused scan of common web ports.                 | `-Pn -sT -sV -T4 -p 80,443,8080,8443,8000,8888,3000,5000 --script=http-title,http-headers,...` |
| 5  | Vulnerability |  no  | NSE vulnerability scripts over versioned services.       | `-Pn -sT -sV -T4 --script=vuln`                                                                 |
| 6  | Stealth SYN   | yes  | Half-open SYN scan of the top 1000 ports.                | `-Pn -sS -sV -T4 --top-ports 1000`                                                             |
| 7  | OS & service  | yes  | SYN scan with OS fingerprinting and service detection.   | `-Pn -sS -sV -O -T4`                                                                            |
| 8  | Aggressive    | yes  | OS, versions, default scripts, and traceroute.           | `-Pn -A -T4`                                                                                    |
| 9  | UDP top       | yes  | Top 50 UDP services (DNS, SNMP, NTP, and so on).         | `-Pn -sU -sV -T4 --top-ports 50`                                                              |
| 10 | Deep audit    | yes  | Full-port SYN scan with OS detection and vuln scripts.   | `-Pn -sS -sV -O -p- -T4 --script=default,vuln`                                                  |

The profile selects the nmap arguments. nmap runs, the open-port data is pulled from
the scan result, and that data is handed to the AI engine for analysis. If a scan
completes but finds no open ports, GVA says so clearly instead of returning a blank
analysis, so an empty result never looks like a silent failure.

## Usage (GUI)

The desktop GUI is built with customtkinter.

```bash
uv run python GVA_gui.py
```

Pick a scan from the left sidebar, fill in the target, and run. Each scan shows only
the fields it needs:

- **Target** for every scan (IP, hostname, domain, token, or capture-file path).
- **AI provider** dropdown for the nmap, DNS, and JWT scans (choose one, or `all`).
- **Nmap profile** dropdown for nmap scans, with a description under it and a note when
  a profile needs root.
- **Wordlist** or **output path** for the subdomain and PCAP scans.

The sidebar also lists the AI providers with a status dot, so you can see at a glance
which keys are configured. Scans run on a background thread, so the window stays
responsive, and results render into a console-style panel with Copy and Clear buttons.
A status bar reports progress and any errors.

## Example output

<details>
<summary>Nmap</summary>

```text
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Elements           ┃ Results                                             ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ critical score     │ High                                                │
│ os information      │ Microsoft Windows 11 21H2                           │
│ open ports          │ 80, 22, 445, 902, 912                               │
│ open services       │ http, ssh, microsoft-ds, vmware-auth                │
│ vulnerable service  │ OpenSSH                                             │
│ found cve           │ CVE-2023-28531                                      │
└────────────────────┴─────────────────────────────────────────────────────┘
```

</details>

<details>
<summary>DNS</summary>

```text
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Elements ┃ Results                                                         ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ A        │ 172.67.147.95, 104.21.41.132                                    │
│ NS       │ mia.ns.cloudflare.com, paul.ns.cloudflare.com                   │
│ MX       │ 10 aspmx.l.google.com, 20 alt1.aspmx.l.google.com               │
│ SOA      │ mia.ns.cloudflare.com dns.cloudflare.com                        │
│ TXT      │ include:_spf.atlassian.net                                      │
└──────────┴─────────────────────────────────────────────────────────────────┘
```

</details>

<details>
<summary>JWT</summary>

```text
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Variables           ┃ Results                                            ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Algorithm Used      │ HS256                                              │
│ PossibleAttacks     │ alg:none downgrade, weak HMAC secret brute force   │
│ VulnerableEndpoints │ any endpoint trusting the token signature          │
└─────────────────────┴──────────────────────────────────────────────────────┘
```

</details>

<details>
<summary>GeoIP</summary>

```text
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Identifiers      ┃ Data                          ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ ip               │ 8.8.8.8                       │
│ continent_name   │ North America                 │
│ country_name     │ United States                 │
│ state_prov       │ California                    │
│ city             │ Mountain View                 │
│ zipcode          │ 94043                         │
│ latitude         │ 37.42240                      │
│ longitude        │ -122.08421                    │
│ isp              │ Google LLC                    │
│ organization     │ Google LLC                    │
│ time_zone.name   │ America/Los_Angeles           │
│ currency.code    │ USD                           │
└──────────────────┴─────────────────────────────────┘
```

</details>

## Python package (GVA)

The `package/` directory publishes the toolkit as the importable `GVA` package.

```bash
cd package && pip install .
```

```python
from GVA.ai_providers import AIEngine, config_from_keys
from GVA.port_scanner import NetworkScanner
from GVA.dns_recon import DNSRecon
from GVA.jwt import JWTAnalyzer
from GVA.subdomain import SubEnum
from GVA import gui

# Build the AI engine from whichever provider keys you have.
engine = AIEngine(config_from_keys(
    openai_key="...",
    anthropic_key="...",
    gemini_key="...",
))

# Run a scan and read the consolidated report.
scanner = NetworkScanner()
report = scanner.scanner("scanme.nmap.org", profile=1, engine=engine, providers=["openai"])
print(report.primary)

# DNS and JWT follow the same pattern.
dns = DNSRecon().dns_resolver("example.com", engine, ["openai"])
subs = SubEnum().sub_enumerator("example.com", "lists/default.txt")

# Or launch the GUI.
gui.launch()
```

Installing the package also provides the `gva` console command, equivalent to running
`gpt_vuln.py`.

## Contributing

Issues and pull requests are welcome. See `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.
For security reports, see `SECURITY.md`.

## Disclaimer

GVA is for authorized security testing and education only. Scan and analyse systems
you own or have explicit permission to test.

## License

MIT. See `LICENSE`.
