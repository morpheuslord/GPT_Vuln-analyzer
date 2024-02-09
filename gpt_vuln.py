import argparse
import os
import cowsay
import hashlib
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
from components.passbeaker import PasswordCracker


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
    parser.add_argument('--attack', type=str, help='Attack type: nmap, dns, sub, jwt, pcap, passcracker')
    parser.add_argument('--sub_list', type=str, default=DEFAULT_LIST_LOC, help='Path to the subdomain list file (txt)')
    parser.add_argument('--output', type=str, default=DEFAULT_OUTPUT_LOC, help='Pcap analysis output file')
    parser.add_argument('--rich_menu', type=str, help='Shows a clean help menu using rich')
    parser.add_argument('--menu', action='store_true', default=False, help='Terminal Interactive Menu')
    parser.add_argument('--ai', type=str, default='openai', help='AI options: openai, bard, llama, llama-api')
    parser.add_argument('--password_hash', help='Password hash')
    parser.add_argument('--wordlist_file', help='Wordlist File')
    parser.add_argument('--algorithm', choices=hashlib.algorithms_guaranteed, help='Hash algorithm')
    parser.add_argument('--salt', help='Salt Value')
    parser.add_argument('--parallel', action='store_true', help='Use parallel processing')
    parser.add_argument('--complexity', action='store_true', help='Check for password complexity')
    parser.add_argument('--brute_force', action='store_true', help='Perform a brute force attack')
    parser.add_argument('--min_length', type=int, default=1, help='Minimum password length for brute force attack')
    parser.add_argument('--max_length', type=int, default=6, help='Minimum password length for brute force attack')
    parser.add_argument('--character_set', default='abcdefghijklmnopqrstuvwxyz0123456789',
                        help='Character set for brute force attack')

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
        packet_analysis.perform_full_analysis(
            pcap_path=target,
            json_path=additional_params.get('output_loc'),
        )
        return "Done"
    elif attack_type == 'passcracker':
        hash = additional_params.get('password_hash')
        wordlist = additional_params.get('wordlist_file')
        salt = additional_params.get('salt')
        parallel = additional_params.get('parallel')
        complexity = additional_params.get('complexity')
        min_length = additional_params.get('min_length')
        max_length = additional_params.get('max_length')
        character_set = additional_params.get('charecter_set')
        brute_force = additional_params.get('brute_force')
        algorithm = additional_params.get('algorithm')
        Cracker = PasswordCracker(
            password_hash=hash,
            wordlist_file=wordlist,
            algorithm=algorithm,
            salt=salt,
            parallel=parallel,
            complexity_check=complexity
        )
        if brute_force:
            Cracker.crack_passwords_with_brute_force(min_length, max_length, character_set)
        else:
            Cracker.crack_passwords_with_wordlist()
        Cracker.print_statistics()


def main() -> None:
    asset_codes.run_docker_container()
    args = parse_arguments()
    api_keys = get_api_keys()
    asset_codes.clearscr()
    cowsay.cow('GVA Usage in progress...')
    target = args.target or '127.0.0.1'
    try:
        if args.rich_menu == "help":
            asset_codes.help_menu()
        elif args.menu is True:
            Menus(
                lkey="",
                threads=4,
                output_loc="",
                lendpoint="",
                keyset="",
                t="",
                profile_num="",
                ai_set="",
                akey_set="",
                bkey_set="",
                ai_set_args="",
                llamakey="",
                llamaendpoint="",
                password_hash="",
                salt="",
                wordlist_loc="",
                algorithm="",
                parallel_proc=True,
                complexity=True,
                min_length=1,
                max_length=6,
                char_set="abcdefghijklmnopqrstuvwxyz0123456789",
                bforce=True
            )
        else:
            additional_params = {
                'profile': args.profile,
                'list_loc': args.sub_list,
                'output_loc': args.output,
                'password_hash': args.password_hash,
                'salt': args.salt,
                'parallel': args.parallel,
                'complexity': args.complexity,
                'brute_force': args.brute_force,
                'min_length': args.min_length,
                'max_lenght': args.max_length,
                'character_set': args.character_set,
                'algorithm': args.algorithm,
                'wordlist_file': args.wordlist_file,
            }
            handle_attack(args.attack, target, args.ai, api_keys, additional_params)
    except KeyboardInterrupt:
        console.print_exception("Bye")
        quit()


if __name__ == "__main__":
    main()
