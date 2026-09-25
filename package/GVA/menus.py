import hashlib
import os
from typing import List

from dotenv import load_dotenv
from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from GVA.ai_providers import AIEngine, PROVIDER_CLASSES, config_from_keys, normalize_selection
from GVA.assets import Assets
from GVA.dns_recon import DNSRecon
from GVA.geo import geo_ip_recon
from GVA.jwt import JWTAnalyzer
from GVA.packet_analysis import PacketAnalysis
from GVA.passbeaker import PasswordCracker
from GVA.port_scanner import NetworkScanner, profile_choices
from GVA.subdomain import SubEnum

console = Console()
load_dotenv()

# Which env var (if any) holds the API key for each provider.
ENV_KEYS = {
    'openai': 'OPENAI_API_KEY',
    'claude': 'ANTHROPIC_API_KEY',
    'gemini': 'GEMINI_API_KEY',
}


class Menus:
    """Interactive terminal front-end for GVA."""

    def __init__(self) -> None:
        self.assets = Assets()
        self.dns = DNSRecon()
        self.geo = geo_ip_recon()
        self.pcap = PacketAnalysis()
        self.jwt = JWTAnalyzer()
        self.scanner = NetworkScanner()
        self.sub = SubEnum()
        self.config = config_from_keys(
            openai_key=os.getenv('OPENAI_API_KEY'),
            anthropic_key=os.getenv('ANTHROPIC_API_KEY'),
            gemini_key=os.getenv('GEMINI_API_KEY') or os.getenv('BARD_API_KEY'),
        )
        self.engine = AIEngine(self.config, progress=True)
        self.main_menu()

    # ------------------------------------------------------------------ helpers
    def _select_providers(self) -> List[str]:
        keys = list(PROVIDER_CLASSES)
        table = Table(title="Available AI providers")
        table.add_column("#", style="cyan")
        table.add_column("Provider", style="green")
        for index, key in enumerate(keys, 1):
            table.add_row(str(index), PROVIDER_CLASSES[key].label)
        console.print(table)
        console.print("Pick one or many: numbers (1,3), names (openai,claude), or 'all'.")
        choice = Prompt.ask("Providers", default="openai")

        selected: List[str] = []
        for part in choice.split(','):
            part = part.strip()
            if part.isdigit() and 1 <= int(part) <= len(keys):
                selected.append(keys[int(part) - 1])
            else:
                selected.append(part)

        providers = normalize_selection(selected) or ['openai']
        self._ensure_keys(providers)
        return providers

    def _ensure_keys(self, providers: List[str]) -> None:
        """Prompt for any credentials a selected provider still needs."""
        for provider in providers:
            if ENV_KEYS.get(provider) and not self.config[provider].get('api_key'):
                key = Prompt.ask(f"Enter API key for {PROVIDER_CLASSES[provider].label}",
                                 password=True, default="")
                if key:
                    self.config[provider]['api_key'] = key
        self.engine = AIEngine(self.config, progress=True)

    # -------------------------------------------------------------------- menus
    def main_menu(self) -> None:
        table = Table(title="GVA Interactive Menu")
        table.add_column("Option", style="cyan")
        table.add_column("Action", style="green")
        actions = {
            "1": ("Nmap scan + AI analysis", self.nmap_menu),
            "2": ("DNS recon + AI analysis", self.dns_menu),
            "3": ("Subdomain enumeration", self.sub_menu),
            "4": ("GeoIP lookup", self.geo_menu),
            "5": ("JWT analysis + AI", self.jwt_menu),
            "6": ("PCAP analysis", self.pcap_menu),
            "7": ("Hash cracker", self.hash_menu),
        }
        for key, (label, _) in actions.items():
            table.add_row(key, label)
        table.add_row("q", "Quit")
        console.print(table)

        choice = Prompt.ask("Enter your choice", choices=[*actions, "q"], default="q")
        if choice == "q":
            return
        try:
            actions[choice][1]()
        except KeyboardInterrupt:
            print(Panel("Exiting Program"))

    def nmap_menu(self) -> None:
        target = Prompt.ask("Target IP/hostname", default="127.0.0.1")
        table = Table(title="Nmap scan profiles")
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Name", style="green")
        table.add_column("Root", justify="center")
        table.add_column("What it does")
        for p in profile_choices():
            table.add_row(str(p.number), p.name, "yes" if p.needs_root else "—", p.description)
        console.print(table)
        profile = IntPrompt.ask("Nmap profile (1-10)", default=1)
        providers = self._select_providers()
        report = self.scanner.scanner(target, profile, self.engine, providers)
        self.assets.render_analysis("Nmap", report)

    def dns_menu(self) -> None:
        target = Prompt.ask("Target domain")
        providers = self._select_providers()
        report = self.dns.dns_resolver(target, self.engine, providers)
        self.assets.render_analysis("DNS", report)

    def jwt_menu(self) -> None:
        token = Prompt.ask("JWT token")
        providers = self._select_providers()
        report = self.jwt.analyze(token, self.engine, providers)
        self.assets.render_analysis("JWT", report)

    def sub_menu(self) -> None:
        list_loc = Prompt.ask("Subdomain wordlist path", default="lists/default.txt")
        target = Prompt.ask("Target domain")
        output = self.sub.sub_enumerator(target, list_loc)
        console.print(output, style="bold underline")

    def geo_menu(self) -> None:
        key = os.getenv("GEOIP_API_KEY") or Prompt.ask("GeoIP API key", password=True)
        target = Prompt.ask("Target IP")
        output = self.geo.geoip(key, target)
        self.assets.render_report("GeoIP", str(output))

    def pcap_menu(self) -> None:
        pcap_path = Prompt.ask("PCAP file path")
        output_loc = Prompt.ask("Output JSON path", default="outputs/output.json")
        self.pcap.perform_full_analysis(pcap_path=pcap_path, json_path=output_loc)

    def hash_menu(self) -> None:
        password_hash = Prompt.ask("Password hash")
        algorithm = Prompt.ask("Algorithm", choices=sorted(hashlib.algorithms_guaranteed), default="md5")
        salt = Prompt.ask("Salt (blank for none)", default="") or None
        parallel = Confirm.ask("Use parallel processing?", default=False)
        complexity = Confirm.ask("Enforce password complexity?", default=False)
        brute_force = Confirm.ask("Brute force (else wordlist)?", default=False)

        if brute_force:
            min_length = IntPrompt.ask("Min length", default=1)
            max_length = IntPrompt.ask("Max length", default=4)
            char_set = Prompt.ask("Character set", default="abcdefghijklmnopqrstuvwxyz0123456789")
            cracker = PasswordCracker(password_hash, None, algorithm, salt, parallel, complexity)
            cracker.crack_passwords_with_brute_force(min_length, max_length, char_set)
        else:
            wordlist = Prompt.ask("Wordlist file path")
            cracker = PasswordCracker(password_hash, wordlist, algorithm, salt, parallel, complexity)
            cracker.crack_passwords_with_wordlist()
        cracker.print_statistics()
