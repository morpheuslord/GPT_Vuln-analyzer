import argparse
import hashlib
import os

import cowsay
from dotenv import load_dotenv
from rich.console import Console

from components.ai_providers import AIEngine, PROVIDER_CLASSES, config_from_keys, normalize_selection
from components.assets import Assets
from components.dns_recon import DNSRecon
from components.geo import geo_ip_recon
from components.jwt import JWTAnalyzer
from components.menus import Menus
from components.packet_analysis import PacketAnalysis
from components.passbeaker import PasswordCracker
from components.port_scanner import NetworkScanner, profile_choices
from components.subdomain import SubEnum

CURRENT_DIR = os.getcwd()
DEFAULT_OUTPUT_LOC = os.path.join(CURRENT_DIR, 'outputs', 'output.json')
DEFAULT_LIST_LOC = 'lists/default.txt'
DEFAULT_THREADS = 200
AI_ATTACKS = {'nmap', 'dns', 'jwt'}

console = Console()
load_dotenv()

dns_enum = DNSRecon()
geo_ip = geo_ip_recon()
packet_analysis = PacketAnalysis()
port_scanner = NetworkScanner()
jwt_analyzer = JWTAnalyzer()
sub_recon = SubEnum()
asset_codes = Assets()


def parse_arguments():
    providers = ", ".join(PROVIDER_CLASSES)
    parser = argparse.ArgumentParser(
        description='Nmap and multi-provider LLM integrated vulnerability scanner')
    parser.add_argument('--target', type=str, help='Target IP, hostname, JWT token or pcap file location')
    parser.add_argument('--profile', type=int, default=1, help='Nmap scan profile 1-10 (Default: 1; see --list_profiles)')
    parser.add_argument('--list_profiles', action='store_true', help='List the available nmap scan profiles and exit')
    parser.add_argument('--sudo', action='store_true',
                        help='Force running nmap under sudo (auto-enabled for privileged profiles)')
    parser.add_argument('--attack', type=str, help='Attack type: nmap, dns, sub, jwt, pcap, geo, passcracker')
    parser.add_argument('--sub_list', type=str, default=DEFAULT_LIST_LOC, help='Path to the subdomain list file (txt)')
    parser.add_argument('--output', type=str, default=DEFAULT_OUTPUT_LOC, help='Pcap analysis output file')
    parser.add_argument('--rich_menu', type=str, help='Shows a clean help menu using rich')
    parser.add_argument('--menu', action='store_true', default=False, help='Terminal Interactive Menu')
    parser.add_argument('--ai', type=str, default='openai',
                        help=f'AI providers, comma-separated or "all" (options: {providers})')
    parser.add_argument('--summarizer', type=str, default=None,
                        help='Provider that deliberates when multiple are used (default: first selected)')
    parser.add_argument('--show_individual', action='store_true',
                        help='Also show each model\'s individual analysis, not just the consolidated one')
    parser.add_argument('--password_hash', help='Password hash')
    parser.add_argument('--wordlist_file', help='Wordlist File')
    parser.add_argument('--algorithm', choices=hashlib.algorithms_guaranteed, help='Hash algorithm')
    parser.add_argument('--salt', help='Salt Value')
    parser.add_argument('--parallel', action='store_true', help='Use parallel processing')
    parser.add_argument('--complexity', action='store_true', help='Check for password complexity')
    parser.add_argument('--brute_force', action='store_true', help='Perform a brute force attack')
    parser.add_argument('--min_length', type=int, default=1, help='Minimum password length for brute force attack')
    parser.add_argument('--max_length', type=int, default=6, help='Maximum password length for brute force attack')
    parser.add_argument('--character_set', default='abcdefghijklmnopqrstuvwxyz0123456789',
                        help='Character set for brute force attack')

    return parser.parse_args()


def list_profiles() -> None:
    from rich.table import Table
    table = Table(title="Nmap scan profiles", header_style="bold")
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Name", style="green")
    table.add_column("Root", justify="center")
    table.add_column("What it does")
    table.add_column("Nmap args", style="dim")
    for p in profile_choices():
        table.add_row(str(p.number), p.name, "yes" if p.needs_root else "—", p.description, p.args)
    console.print(table)


def build_engine(summarizer=None):
    return AIEngine(config_from_keys(
        openai_key=os.getenv('OPENAI_API_KEY'),
        anthropic_key=os.getenv('ANTHROPIC_API_KEY'),
        gemini_key=os.getenv('GEMINI_API_KEY') or os.getenv('BARD_API_KEY'),
    ), summarizer=summarizer, progress=True)


def resolve_providers(selection: str) -> list:
    providers = normalize_selection(selection)
    if not providers:
        console.print(f"[yellow]No valid AI provider in '{selection}'. Falling back to openai.[/yellow]")
        providers = ['openai']
    return providers


def handle_attack(args, engine, providers) -> None:
    attack_type = args.attack
    target = args.target or '127.0.0.1'

    if attack_type == 'geo':
        output = geo_ip.geoip(os.getenv('GEOIP_API_KEY'), target)
        asset_codes.render_report('GeoIP', output)
    elif attack_type == 'nmap':
        report = port_scanner.scanner(target, args.profile, engine, providers, sudo=args.sudo)
        asset_codes.render_analysis('Nmap', report, show_individual=args.show_individual)
    elif attack_type == 'dns':
        report = dns_enum.dns_resolver(target, engine, providers)
        asset_codes.render_analysis('DNS', report, show_individual=args.show_individual)
    elif attack_type == 'sub':
        output = sub_recon.sub_enumerator(target, args.sub_list)
        console.print(output, style="bold underline")
    elif attack_type == 'jwt':
        report = jwt_analyzer.analyze(target, engine, providers)
        asset_codes.render_analysis('JWT', report, show_individual=args.show_individual)
    elif attack_type == 'pcap':
        packet_analysis.perform_full_analysis(pcap_path=target, json_path=args.output)
    elif attack_type == 'passcracker':
        cracker = PasswordCracker(
            password_hash=args.password_hash,
            wordlist_file=args.wordlist_file,
            algorithm=args.algorithm,
            salt=args.salt,
            parallel=args.parallel,
            complexity_check=args.complexity,
        )
        if args.brute_force:
            cracker.crack_passwords_with_brute_force(args.min_length, args.max_length, args.character_set)
        else:
            cracker.crack_passwords_with_wordlist()
        cracker.print_statistics()
    else:
        console.print(f"[red]Unknown attack type: {attack_type}[/red]")


def main() -> None:
    args = parse_arguments()
    if args.list_profiles:
        list_profiles()
        return
    asset_codes.clearscr()
    cowsay.cow('GVA Usage in progress...')

    try:
        if args.rich_menu == "help":
            asset_codes.help_menu()
            return
        if args.menu:
            Menus()
            return

        engine = build_engine(summarizer=args.summarizer)
        providers = resolve_providers(args.ai) if args.attack in AI_ATTACKS else []
        # Only spin up the local Ollama container when it is actually requested.
        if 'ollama' in providers:
            asset_codes.run_docker_container()
        handle_attack(args, engine, providers)
    except KeyboardInterrupt:
        console.print("Bye")


if __name__ == "__main__":
    main()
