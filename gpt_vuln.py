import argparse
import cowsay
import commands.domain as domain
import commands.port_scanner as ports
from rich.console import Console
from rich.table import Table
from commands.port_scanner import scanner
from commands.domain import dnsr
from commands.geo import geoip
from commands.subdomain import sub
from typing import Any


console = Console()
gkey = "__API__KEY__"
akey = "__API__KEY__"
ports.openai.api_key = akey
domain.openai.api_key = akey

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
parser.add_argument('--r', metavar='r', type=str,
                    help='Shows a more clean help manu using rich only argument-input is help', default=help, required=False)
args = parser.parse_args()

target = args.target
profile = args.profile
attack = args.attack
choice = args.r


def rt() -> None:
    table = Table(title="Help Menu for GVA")
    table.add_column("Options")
    table.add_column("Input Type")
    table.add_column("Argument Input")
    table.add_column("Discription")
    table.add_column("Other internal options")
    table.add_row("Attack", "--attack", "TXT/STRING",
                  "The Attack the user whats to run", "sub / dns / nmap / geo")
    table.add_row("Target", "--target", "IP/HOSTNAME",
                  "The target of the user", "None")
    table.add_row("Profile", "--profile", "INT (1-5)",
                  "The type of Nmap Scan the user intends", "None")
    table.add_row("Rich Help", "--r", "STRING",
                  "Pritty Help menu", "help")
    console.print(table)


def main(target: Any) -> None:
    cowsay.cow('GVA Usage in progress...')
    try:
        if choice == "help":
            rt()
        else:
            match attack:
                case 'geo':
                    final = geoip(gkey, target)
                    print(final)
                case 'nmap':
                    match profile:
                        case 1:
                            final = scanner(target, 1)
                            print(final)
                        case 2:
                            final = scanner(target, 2)
                            print(final)
                        case 3:
                            final = scanner(target, 3)
                            print(final)
                        case 4:
                            final = scanner(target, 4)
                            print(final)
                        case 5:
                            final = scanner(target, 5)
                            print(final)
                case 'dns':
                    final = dnsr(target)
                    print(final)
                case 'sub':
                    final = sub(target)
                    console.print(final, style="bold underline")
    except KeyboardInterrupt:
        console.print_exception("Bye")
        quit()


if __name__ == "__main__":
    main(target)
