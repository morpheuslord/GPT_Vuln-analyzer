import argparse
import os
import cowsay
from dotenv import load_dotenv
from rich.console import Console
from components.dns_recon import DNSRecon
from components.geo import geo_ip_recon
from components.port_scanner import NetworkScanner
from components.jwt import JWTAnalyzer
from components.packet_analysis import PacketAnalysis
from components.subdomain import SubEnum
from components.menus import Menus
from components.assets import Assets

CURRENT_DIR = os.getcwd()
DEFAULT_OUTPUT_LOC = os.path.join(CURRENT_DIR, 'outputs', 'output.json')
DEFAULT_LIST_LOC = 'lists/default.txt'
DEFAULT_THREADS = 200

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
    parser = argparse.ArgumentParser(
        description='Python-Nmap and chatGPT integrated Vulnerability scanner')
    parser.add_argument('--target', type=str, help='Target IP, hostname, JWT token or pcap file location')
    parser.add_argument('--profile', type=int, default=1, help='Enter Profile of scan 1-13 (Default: 1)')
    parser.add_argument('--attack', type=str, help='Attack type: nmap, dns, sub, jwt, pcap')
    parser.add_argument('--list', type=str, default=DEFAULT_LIST_LOC, help='Path to the subdomain list file (txt)')
    parser.add_argument('--output', type=str, default=DEFAULT_OUTPUT_LOC, help='Pcap analysis output file')
    parser.add_argument('--threads', type=int, default=DEFAULT_THREADS, help='Number of threads for pcap processing')
    parser.add_argument('--rich_menu', type=str, help='Shows a clean help menu using rich')
    parser.add_argument('--menu', type=bool, default=False, help='Terminal Interactive Menu')
    parser.add_argument('--ai', type=str, default='openai', help='AI options: openai, bard, llama, llama-api')
    return parser.parse_args()


def get_api_keys():
    return {
        'geoip_api_key': os.getenv('GEOIP_API_KEY'),
        'openai_api_key': os.getenv('OPENAI_API_KEY'),
        'bard_api_key': os.getenv('BARD_API_KEY'),
        'runpod_api_key': os.getenv('RUNPOD_API_KEY'),
        'runpod_endpoint_id': os.getenv('RUNPOD_ENDPOINT_ID')
    }


def handle_attack(attack_type, target, ai, api_keys, additional_params=None):
    additional_params = additional_params or {}

    if attack_type == 'geo':
        output = geo_ip.geoip(api_keys['geoip_api_key'], target)
        asset_codes.print_output(attack_type.capitalize(), str(output), ai)
    elif attack_type == 'nmap':
        output = port_scanner.scanner(
            ip=target,
            profile=additional_params.get('profile'),
            akey=api_keys['openai_api_key'],
            bkey=api_keys['bard_api_key'],
            lkey=api_keys['runpod_api_key'],
            lendpoint=api_keys['runpod_endpoint_id'],
            AI=ai
        )
        asset_codes.print_output(attack_type.capitalize(), str(output), ai)
    elif attack_type == 'dns':
        output = dns_enum.dns_resolver(
            target=target,
            akey=api_keys['openai_api_key'],
            bkey=api_keys['bard_api_key'],
            lkey=api_keys['runpod_api_key'],
            lendpoint=api_keys['runpod_endpoint_id'],
            AI=ai
        )
        asset_codes.print_output(attack_type.capitalize(), str(output), ai)
    elif attack_type == 'sub':
        output = sub_recon.sub_enumerator(target, additional_params.get('list_loc'))
        console.print(output, style="bold underline")
        asset_codes.print_output(attack_type.capitalize(), str(output), ai)
    elif attack_type == 'jwt':
        output = jwt_analyzer.analyze(
            token=target,
            openai_api_token=api_keys['openai_api_key'],
            bard_api_token=api_keys['bard_api_key'],
            llama_api_token=api_keys['runpod_api_key'],
            llama_endpoint=api_keys['runpod_endpoint_id'],
            AI=ai
        )
        asset_codes.print_output("JWT", output, ai)
    elif attack_type == 'pcap':
        packet_analysis.PacketAnalyzer(
            cap_loc=target,
            save_loc=additional_params.get('output_loc'),
            max_workers=additional_params.get('threads')
        )
        return "Done"


def main() -> None:
    args = parse_arguments()
    api_keys = get_api_keys()

    cowsay.cow('GVA Usage in progress...')
    target = args.target or '127.0.0.1'

    try:
        if args.rich_menu == "help":
            asset_codes.help_menu()
        elif args.menu:
            Menus(
                lkey=api_keys['runpod_api_key'],
                threads=args.threads,
                output_loc=args.output,
                lendpoint=api_keys['runpod_endpoint_id'],
                keyset="",
                t="",
                profile_num="",
                ai_set="",
                akey_set="",
                bkey_set="",
                ai_set_args="",
                llamakey="",
                llamaendpoint=""
            )
        else:
            additional_params = {
                'profile': args.profile,
                'list_loc': args.list,
                'output_loc': args.output,
                'threads': args.threads
            }
            handle_attack(args.attack, target, args.ai, api_keys, additional_params)
    except KeyboardInterrupt:
        console.print_exception("Bye")
        quit()


if __name__ == "__main__":
    main()
