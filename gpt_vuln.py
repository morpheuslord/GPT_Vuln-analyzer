import argparse
import os
from typing import Any

import cowsay
from dotenv import load_dotenv
from rich.console import Console

from commands.dns_recon import DNSRecon
from commands.geo import geo_ip_recon
from commands.port_scanner import NetworkScanner
from commands.jwt import JWTAnalyzer
from commands.models import NMAP_AI_MODEL
from commands.models import DNS_AI_MODEL
from commands.models import JWT_AI_MODEL
from commands.subdomain import sub_enum
from commands.menus import Menus
from commands.assets import Assets

console = Console()
dns_enum = DNSRecon()
geo_ip = geo_ip_recon()
p_ai_models = NMAP_AI_MODEL()
dns_ai_models = DNS_AI_MODEL()
jwt_ai_models = JWT_AI_MODEL()
port_scanner = NetworkScanner()
jwt_analizer = JWTAnalyzer()
sub_recon = sub_enum()
asset_codes = Assets()
load_dotenv()

# The API Keys
gkey = os.getenv('GEOIP_API_KEY')
akey = os.getenv('OPENAI_API_KEY')
bkey = os.getenv('BARD_API_KEY')
lkey = os.getenv('RUNPOD_API_KEY')
lendpoint = os.getenv('RUNPOD_ENDPOINT_ID')

parser = argparse.ArgumentParser(
    description='Python-Nmap and chatGPT intigrated Vulnerability scanner')
parser.add_argument('--target', metavar='target', type=str,
                    help='Target IP or hostname or JWT token')
parser.add_argument('--profile', metavar='profile', type=int, default=1,
                    help='Enter Profile of scan 1-13 (Default: 1)', required=False)
parser.add_argument('--attack', metavar='attack', type=str,
                    help='''
                    Enter Attack type nmap, dns or sub.
                    sub - Subdomain Enumeration using the default array.
                    dns - to perform DNS Enumeration and get openion from Chat-GPT
                    jwt - Analyze JWT tokens and the related information
                    ''', required=False)
parser.add_argument('--list', metavar='list', type=str,
                    help='''
                    The path to the subdomain list file (txt).
                    ''',
                    default='lists/default.txt',
                    required=False)
parser.add_argument('--rich_menu', metavar='rich_menu', type=str,
                    help='Shows a more clean help manu using rich only argument-input is help',
                    default=help,
                    required=False)
parser.add_argument('--menu', metavar='menu', type=bool,
                    help='Terminal Interactive Menu',
                    required=False,
                    default=False)
parser.add_argument('--ai', metavar='ai', type=str,
                    help='AI options for ("openai" Default, "bard", "llama", "llama-api")',
                    required=False,
                    default='openai')
args = parser.parse_args()

target = args.target
profile = args.profile
attack = args.attack
choice = args.rich_menu
list_loc = args.list
ai = args.ai
menu = args.menu
ai_set_args = ""
keyset = ""
akey_set = ""
bkey_set = ""
t = ""
profile_num = ""
ai_set = ""
llamakey = ""
llamaendpoint = ""


def main(target: Any) -> None:
    if ai == "llama":
        asset_codes.start_api_app()
    cowsay.cow('GVA Usage in progress...')
    if target is not None:
        pass
    else:
        target = '127.0.0.1'
    try:
        if choice == "help":
            asset_codes.help_menu()
        elif menu is True:
            Menus(
                lkey=lkey,
                lendpoint=lendpoint,
                keyset=keyset,
                t=t,
                profile_num=profile_num,
                ai_set=ai_set,
                akey_set=akey_set,
                bkey_set=bkey_set,
                ai_set_args=ai_set_args,
                llamakey=llamakey,
                llamaendpoint=llamaendpoint
            )
        else:
            match attack:
                case 'geo':
                    geo_output: str = geo_ip_recon.geoip(gkey, target)
                    asset_codes.print_output("GeoIP", str(geo_output), ai)
                case 'nmap':
                    p1_out = port_scanner.scanner(
                        AIModels=p_ai_models,
                        ip=target,
                        profile=int(profile),
                        akey=akey,
                        bkey=bkey,
                        lkey=lkey,
                        lendpoint=lendpoint,
                        AI=ai
                    )
                    asset_codes.print_output("Nmap", p1_out, ai)
                case 'dns':
                    dns_output: str = dns_enum.dns_resolver(
                        AIModels=dns_ai_models,
                        target=target,
                        akey=akey,
                        bkey=bkey,
                        lkey=lkey,
                        lendpoint=lendpoint,
                        AI=ai
                    )
                    asset_codes.print_output("DNS", dns_output, ai)
                case 'sub':
                    sub_output: str = sub_recon.sub_enumerator(target, list_loc)
                    console.print(sub_output, style="bold underline")
                case 'jwt':
                    output: str = jwt_analizer.analyze(
                        AIModels=jwt_ai_models,
                        token=target,
                        openai_api_token=akey,
                        bard_api_token=bkey,
                        llama_api_token=lkey,
                        llama_endpoint=lendpoint,
                        AI=ai
                    )
                    asset_codes.print_output("JWT", output, ai)
    except KeyboardInterrupt:
        console.print_exception("Bye")
        quit()


if __name__ == "__main__":
    main(target)
