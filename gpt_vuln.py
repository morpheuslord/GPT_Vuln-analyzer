import argparse
import json
import os
import platform
from typing import Any

import cowsay
import subprocess
from dotenv import load_dotenv
from rich import print
from rich.console import Console
from rich.panel import Panel
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
bkey = os.getenv('BARD_API_KEY')  # BardAPI KEY
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
parser.add_argument('--menu', metavar='menu', type=bool,
                    help='Terminal Interactive Menu',
                    required=False,
                    default=False)
parser.add_argument('--ai', metavar='ai', type=str,
                    help='Terminal Interactive Menu',
                    required=False,
                    default='openai')
args = parser.parse_args()

target = args.target
profile = args.profile
attack = args.attack
choice = args.r
list_loc = args.list
ai = args.ai
menu = args.menu
keyset = ""
akey_set = ""
bkey_set = ""
t = ""
profile_num = ""
ai_set = ""


def clearscr() -> None:
    try:
        osp = platform.system()
        match osp:
            case 'Darwin':
                os.system("clear")
            case 'Linux':
                os.system("clear")
            case 'Windows':
                os.system("cls")
    except Exception:
        pass


def start_api_app():
    if os.name == 'nt':
        CREATE_NEW_CONSOLE = 0x00000010
        subprocess.Popen(["python", "llama_api.py"], creationflags=CREATE_NEW_CONSOLE)


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
    table.add_row("AI", "--ai", "STRING",
                  "Choose your AI of choice", "bard / openai (default)")
    table.add_row("menu", "--menu", "BOOL",
                  "Interactive UI menu", "True / False (Default)")
    table.add_row("Rich Help", "--r", "STRING",
                  "Pritty Help menu", "help")
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


def nmap_menu() -> None:
    try:
        global keyset
        global t
        global profile_num
        global ai_set
        global akey_set
        global bkey_set
        table = Table()
        table.add_column("Options", style="cyan")
        table.add_column("Utility", style="green")
        table.add_row("1", "AI Options")
        table.add_row("2", "Set Target")
        table.add_row("3", "Set Profile")
        table.add_row("4", "Show options")
        table.add_row("5", "Run Attack")
        table.add_row("r", "Return")
        console.print(table)
        option = input("Enter your choice: ")
        match option:
            case "1":
                clearscr()
                table0 = Table()
                table0.add_column("Options", style="cyan")
                table0.add_column("AI Available", style="green")
                table0.add_row("1", "OpenAI")
                table0.add_row("2", "Bard")
                print(Panel(table0))
                ai_set_choice = input("Enter AI of Choice: ")
                if ai_set_choice == "1":
                    ai_set = "openai"
                    akey_set = input("Enter OpenAI API: ")
                    print(Panel(f"OpenAI-Key Set: {akey_set}"))
                else:
                    ai_set = "bard"
                    bkey_set = input("Enter Bard AI API: ")
                    print(Panel(f"BardAI-Key Set: {bkey_set}"))
                nmap_menu()
            case "2":
                clearscr()
                print(Panel("Set Target Hostname or IP"))
                t = input("Enter Target: ")
                print(Panel(f"Target Set: {t}"))
                nmap_menu()
            case "3":
                clearscr()
                table1 = Table()
                table1.add_column("Options", style="cyan")
                table1.add_column("Value", style="green")
                table1.add_row("1", "-Pn -sV -T4 -O -F")
                table1.add_row("2", "-Pn -T4 -A -v")
                table1.add_row("3", "-Pn -sS -sU -T4 -A -v")
                table1.add_row("4", "-Pn -p- -T4 -A -v")
                table1.add_row("5", "-Pn -sS -sU -T4 -A -PE -PP  -PY -g 53 --script=vuln")
                print(Panel(table1))
                profile_num = input("Enter your Profile: ")
                print(Panel(f"Profile Set {profile_num}"))
                nmap_menu()
            case "4":
                clearscr()
                table2 = Table()
                table2.add_column("Options", style="cyan")
                table2.add_column("Value", style="green")
                table2.add_row("OpenAI API Key", str(akey_set))
                table2.add_row("Bard AI API Key", str(bkey_set))
                table2.add_row("Target", str(t))
                table2.add_row("Profile", str(profile_num))
                # console.print(table2)
                print(Panel(table2))
                nmap_menu()
            case "5":
                clearscr()
                pout: str = p_scanner(t, int(profile_num), akey_set, bkey_set, ai_set)
                print_output("Nmap", pout)
            case "r":
                clearscr()
                menu_term()
    except KeyboardInterrupt:
        print(Panel("Exiting Program"))


def dns_menu() -> None:
    try:
        global keyset
        global t
        global profile_num
        global ai_set
        global akey_set
        global bkey_set
        table = Table()
        table.add_column("Options", style="cyan")
        table.add_column("Utility", style="green")
        table.add_row("1", "AI Option")
        table.add_row("2", "Set Target")
        table.add_row("3", "Show options")
        table.add_row("4", "Run Attack")
        table.add_row("r", "Return")
        console.print(table)
        option = input("Enter your choice: ")
        match option:
            case "1":
                clearscr()
                table0 = Table()
                table0.add_column("Options", style="cyan")
                table0.add_column("AI Available", style="green")
                table0.add_row("1", "OpenAI")
                table0.add_row("2", "Bard")
                print(Panel(table0))
                ai_set_choice = input("Enter AI of Choice: ")
                if ai_set_choice == "1":
                    ai_set = "openai"
                    akey_set = input("Enter OpenAI API: ")
                    print(Panel(f"API-Key Set: {akey_set}"))
                else:
                    ai_set = "bard"
                    bkey_set = input("Enter Bard AI API: ")
                    print(Panel(f"API-Key Set: {bkey_set}"))
                dns_menu()
            case "2":
                clearscr()
                print(Panel("Set Target Hostname or IP"))
                t = input("Enter Target: ")
                print(Panel(f"Target Set:{t}"))
                dns_menu()
            case "3":
                clearscr()
                table1 = Table()
                table1.add_column("Options", style="cyan")
                table1.add_column("Value", style="green")
                table1.add_row("OpenAI API Key", str(akey_set))
                table1.add_row("Bard AI API Key", str(bkey_set))
                table1.add_row("Target", str(t))
                print(Panel(table1))
                dns_menu()
            case "4":
                clearscr()
                dns_output: str = dnsr(t, akey_set, bkey_set, ai_set)
                print_output("DNS", dns_output)
            case "r":
                clearscr()
                menu_term()
    except KeyboardInterrupt:
        print(Panel("Exiting Program"))


def geo_menu() -> None:
    try:
        global keyset
        global t
        global profile_num
        table = Table()
        table.add_column("Options", style="cyan")
        table.add_column("Utility", style="green")
        table.add_row("1", "ADD API Key")
        table.add_row("2", "Set Target")
        table.add_row("3", "Show options")
        table.add_row("4", "Run Attack")
        table.add_row("r", "Return")
        console.print(table)
        option = input("Enter your choice: ")
        match option:
            case "1":
                clearscr()
                keyset = input("Enter GEO-IP API: ")
                print(Panel(f"GEOIP API Key Set: {keyset}"))
                geo_menu()
            case "2":
                clearscr()
                print(Panel("Set Target Hostname or IP"))
                t = input("Enter Target: ")
                print(Panel(f"Target Set: {t}"))
                geo_menu()
            case "3":
                clearscr()
                table1 = Table()
                table1.add_column("Options", style="cyan")
                table1.add_column("Value", style="green")
                table1.add_row("API Key", str(keyset))
                table1.add_row("Target", str(t))
                print(Panel(table1))
                geo_menu()
            case "4":
                clearscr()
                geo_output: str = geoip(keyset, t)
                GEOIP_to_table(str(geo_output))
            case "r":
                clearscr()
                menu_term()
    except KeyboardInterrupt:
        print(Panel("Exiting Program"))


def sub_menu() -> None:
    try:
        global list_loc
        global t
        global profile_num
        table = Table()
        table.add_column("Options", style="cyan")
        table.add_column("Utility", style="green")
        table.add_row("1", "ADD Subdomain list")
        table.add_row("2", "Set Target")
        table.add_row("3", "Show options")
        table.add_row("4", "Run Attack")
        table.add_row("r", "Return")
        console.print(table)
        option = input("Enter your choice: ")
        match option:
            case "1":
                clearscr()
                print(Panel("Set TXT subdomain file location"))
                list_loc = input("Enter List Location:  ")
                print(Panel(f"Location Set: {list_loc}"))
                sub_menu()
            case "2":
                clearscr()
                print(Panel("Set Target Hostname or IP"))
                t = input("Enter Target: ")
                print(Panel(f"Target Set: {t}"))
                sub_menu()
            case "3":
                clearscr()
                table1 = Table()
                table1.add_column("Options", style="cyan")
                table1.add_column("Value", style="green")
                table1.add_row("Location", str(list_loc))
                table1.add_row("Target", str(t))
                print(Panel(table1))
                sub_menu()
            case "4":
                clearscr()
                sub_output: str = sub(t, list_loc)
                console.print(sub_output, style="bold underline")
            case "r":
                clearscr()
                menu_term()
    except KeyboardInterrupt:
        print(Panel("Exiting Program"))


def menu_term() -> None:
    start_api_app()
    try:
        table = Table()
        table.add_column("Options", style="cyan")
        table.add_column("Utility", style="green")
        table.add_row("1", "Nmap Enum")
        table.add_row("2", "DNS Enum")
        table.add_row("3", "Subdomain Enum")
        table.add_row("4", "GEO-IP Enum")
        table.add_row("q", "Quit")
        console.print(table)
        option = input("Enter your choice: ")
        match option:
            case "1":
                clearscr()
                nmap_menu()
            case "2":
                clearscr()
                dns_menu()
            case "3":
                clearscr()
                sub_menu()
            case "4":
                clearscr()
                geo_menu()
            case "q":
                quit()
    except KeyboardInterrupt:
        print(Panel("Exiting Program"))


def print_output(attack_type: str, jdata: str, ai: str) -> Any:
    data = json.loads(jdata)
    table = Table(title=f"GVA Report for {attack_type}", show_header=True, header_style="bold magenta")
    table.add_column("Variables", style="cyan")
    table.add_column("Results", style="green")

    # Iterate over the data and add rows to the table
    for key, value in data.items():
        table.add_row(key, value)
    console.print(table)


def main(target: Any) -> None:
    start_api_app()
    cowsay.cow('GVA Usage in progress...')
    if target is not None:
        pass
    else:
        target = '127.0.0.1'
    try:
        if choice == "help":
            help_menu()
        elif menu is True:
            menu_term()
        else:
            match attack:
                case 'geo':
                    geo_output: str = geoip(gkey, target)
                    GEOIP_to_table(str(geo_output))
                case 'nmap':
                    match profile:
                        case 1:
                            p1_out: str = p_scanner(target, 1, akey, bkey, ai)
                            print_output("Nmap", p1_out)
                        case 2:
                            p2_out: str = p_scanner(target, 2, akey, bkey, ai)
                            print_output("Nmap", p2_out)
                        case 3:
                            p3_out: str = p_scanner(target, 3, akey, bkey, ai)
                            print_output("Nmap", p3_out)
                        case 4:
                            p4_out: str = p_scanner(target, 4, akey, bkey, ai)
                            print_output("Nmap", p4_out)
                        case 5:
                            p5_out: str = p_scanner(target, 5, akey, bkey, ai)
                            print_output("Nmap", p5_out)
                case 'dns':
                    dns_output: str = dnsr(target, akey, bkey, ai)
                    print_output("DNS", dns_output)
                case 'sub':
                    sub_output: str = sub(target, list_loc)
                    console.print(sub_output, style="bold underline")
    except KeyboardInterrupt:
        console.print_exception("Bye")
        quit()


if __name__ == "__main__":
    main(target)
