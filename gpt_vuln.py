import argparse
import json
import os
from typing import Any

import cowsay
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from commands.dns_recon import dnsr
from commands.geo import geoip
from commands.port_scanner import p_scanner
from commands.subdomain import sub

console = Console()
load_dotenv()

# The API Keys
gkey = os.getenv('GEOIP_API_KEY')  # GeoIP API
akey = os.getenv('OPENAI_API_KEY')  # OpenAI API

parser = argparse.ArgumentParser(
    description='Python-Nmap and chatGPT intigrated Vulnerability scanner')
parser.add_argument('--target', metavar='target', type=str,
                    help='Target IP or hostname')
parser.add_argument('--profile', metavar='profile', type=int, default=1,
                    help='Enter Profile of scan 1-5 (Default: 1)', required=False)
parser.add_argument('--attack', metavar='attack', type=str,
                    help='''
                    Enter Attack type nmap, dns or sub.
                    sub - Subdomain Enumeration using the default array.
                    dns - to perform DNS Enumeration and get openion from Chat-GPT
                    ''', required=False)
parser.add_argument('--list', metavar='list', type=str,
                    help='''
                    The path to the subdomain list file (txt).
                    ''',
                    default='lists/default.txt',
                    required=False)
parser.add_argument('--r', metavar='r', type=str,
                    help='Shows a more clean help manu using rich only argument-input is help',
                    default=help,
                    required=False)
args = parser.parse_args()

target = args.target
profile = args.profile
attack = args.attack
choice = args.r
list = args.list


def help_menu() -> None:
    table = Table(title="Help Menu for GVA")
    table.add_column("Options", style="cyan")
    table.add_column("Input Type", style="green")
    table.add_column("Argument Input", style="green")
    table.add_column("Discription", style="green")
    table.add_column("Other internal options", style="green")
    table.add_row("Attack", "--attack", "TXT/STRING",
                  "The Attack the user whats to run", "sub / dns / nmap / geo")
    table.add_row("Target", "--target", "IP/HOSTNAME",
                  "The target of the user", "None")
    table.add_row("Domain List", "--list", "Path to text file",
                  "subdomain dictionary list", "Path")
    table.add_row("Profile", "--profile", "INT (1-5)",
                  "The type of Nmap Scan the user intends", "None")
    table.add_row("Rich Help", "--r", "STRING",
                  "Pritty Help menu", "help")
    console.print(table)


def print_output(attack_type: str, jdata: str) -> Any:
    data = json.loads(jdata)
    table = Table(title=f"GVA Report for {attack_type}", show_header=True, header_style="bold magenta")
    table.add_column("Variables", style="cyan")
    table.add_column("Results", style="green")

    # Iterate over the data and add rows to the table
    for key, value in data.items():
        table.add_row(key, value)

    console.print(table)


def GEOIP_to_table(json_data: str) -> Any:
    data = json.loads(json_data)

    table = Table(title="GVA Report for GeoIP", show_header=True, header_style="bold magenta")
    table.add_column("Identifiers", style="cyan")
    table.add_column("Data", style="green")

    flattened_data: dict = flatten_json(data, separator='.')

    for key, value in flattened_data.items():
        value_str = str(value)
        table.add_row(key, value_str)

    console = Console()
    console.print(table)


def flatten_json(data: Any, separator: Any = '.') -> Any:
    flattened_data = {}
    for key, value in data.items():
        if isinstance(value, dict):
            nested_data = flatten_json(value, separator)
            for nested_key, nested_value in nested_data.items():
                flattened_data[key + separator + nested_key] = nested_value
        else:
            flattened_data[key] = value
    return flattened_data


def main(target: Any) -> None:
    cowsay.cow('GVA Usage in progress...')
    if target is not None:
        pass
    else:
        target = '127.0.0.1'
    try:
        if choice == "help":
            help_menu()
        else:
            match attack:
                case 'geo':
                    geo_output: str = geoip(gkey, target)
                    GEOIP_to_table(str(geo_output))
                case 'nmap':
                    match profile:
                        case 1:
                            p1_out: str = p_scanner(target, 1, akey)
                            print_output("Nmap", p1_out)
                        case 2:
                            p2_out: str = p_scanner(target, 2, akey)
                            print_output("Nmap", p2_out)
                        case 3:
                            p3_out: str = p_scanner(target, 3, akey)
                            print_output("Nmap", p3_out)
                        case 4:
                            p4_out: str = p_scanner(target, 4, akey)
                            print_output("Nmap", p4_out)
                        case 5:
                            p5_out: str = p_scanner(target, 5, akey)
                            print_output("Nmap", p5_out)
                case 'dns':
                    dns_output: str = dnsr(target, akey)
                    print_output("DNS", dns_output)
                case 'sub':
                    sub_output: str = sub(target, list)
                    console.print(sub_output, style="bold underline")
    except KeyboardInterrupt:
        console.print_exception("Bye")
        quit()


if __name__ == "__main__":
    main(target)
