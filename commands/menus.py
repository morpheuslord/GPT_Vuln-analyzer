import json
import os
import platform
from typing import Any
from rich import print
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.console import Group
from rich.align import Align
from rich import box
from rich.markdown import Markdown
from commands.dns_recon import DNSRecon
from commands.geo import geo_ip_recon
from commands.port_scanner import NetworkScanner
from commands.models import NMAP_AI_MODEL
from commands.models import DNS_AI_MODEL
from commands.subdomain import sub_enum

dns_enum = DNSRecon()
geo_ip = geo_ip_recon()
p_ai_models = NMAP_AI_MODEL()
dns_ai_models = DNS_AI_MODEL()
port_scanner = NetworkScanner()
sub_recon = sub_enum()
console = Console()
target = ""
profile = ""
attack = ""
choice = ""
list_loc = ""
ai = ""
menu = ""
ai_set_args = ""
keyset = ""
akey_set = ""
bkey_set = ""
t = ""
profile_num = ""
ai_set = ""
llamakey = ""
llamaendpoint = ""


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


class Menus():
    def flatten_json(self, data: Any, separator: Any = '.') -> Any:
        flattened_data = {}
        for key, value in data.items():
            if isinstance(value, dict):
                nested_data = self.flatten_json(value, separator)
                for nested_key, nested_value in nested_data.items():
                    flattened_data[key + separator + nested_key] = nested_value
            else:
                flattened_data[key] = value
        return flattened_data

    def print_output(self, attack_type: str, jdata: str, ai: str) -> Any:
        match attack_type:
            case "Nmap":
                match ai:
                    case 'openai':
                        data = json.loads(jdata)
                        table = Table(title=f"GVA Report for {attack_type}", show_header=True, header_style="bold magenta")
                        table.add_column("Variables", style="cyan")
                        table.add_column("Results", style="green")

                        for key, value in data.items():
                            table.add_row(key, value)
                        print(table)
                    case 'bard':
                        data = json.loads(jdata)
                        table = Table(title=f"GVA Report for {attack_type}", show_header=True, header_style="bold magenta")
                        table.add_column("Variables", style="cyan")
                        table.add_column("Results", style="green")

                        for key, value in data.items():
                            table.add_row(key, value)
                        print(table)
                    case 'llama':
                        ai_out = Markdown(jdata)
                        message_panel = Panel(
                            Align.center(
                                Group("\n", Align.center(ai_out)),
                                vertical="middle",
                            ),
                            box=box.ROUNDED,
                            padding=(1, 2),
                            title="[b red]The GVA LLama2",
                            border_style="blue",
                        )
                        print(message_panel)
                    case 'llama-api':
                        ai_out = Markdown(jdata)
                        message_panel = Panel(
                            Align.center(
                                Group("\n", Align.center(ai_out)),
                                vertical="middle",
                            ),
                            box=box.ROUNDED,
                            padding=(1, 2),
                            title="[b red]The GVA LLama2",
                            border_style="blue",
                        )
                        print(message_panel)
            case "DNS":
                match ai:
                    case 'openai':
                        data = json.loads(jdata)
                        table = Table(title=f"GVA Report for {attack_type}", show_header=True, header_style="bold magenta")
                        table.add_column("Variables", style="cyan")
                        table.add_column("Results", style="green")

                        for key, value in data.items():
                            table.add_row(key, value)
                        print(table)
                    case 'bard':
                        data = json.loads(jdata)
                        table = Table(title=f"GVA Report for {attack_type}", show_header=True, header_style="bold magenta")
                        table.add_column("Variables", style="cyan")
                        table.add_column("Results", style="green")

                        for key, value in data.items():
                            table.add_row(key, value)
                        print(table)
                    case 'llama':
                        ai_out = Markdown(jdata)
                        message_panel = Panel(
                            Align.center(
                                Group("\n", Align.center(ai_out)),
                                vertical="middle",
                            ),
                            box=box.ROUNDED,
                            padding=(1, 2),
                            title="[b red]The GVA LLama2",
                            border_style="blue",
                        )
                        print(message_panel)
                    case 'llama-api':
                        ai_out = Markdown(jdata)
                        message_panel = Panel(
                            Align.center(
                                Group("\n", Align.center(ai_out)),
                                vertical="middle",
                            ),
                            box=box.ROUNDED,
                            padding=(1, 2),
                            title="[b red]The GVA LLama2",
                            border_style="blue",
                        )
                        print(message_panel)
            case "GeoIP":
                data = json.loads(jdata)
                table = Table(title="GVA Report for GeoIP", show_header=True, header_style="bold magenta")
                table.add_column("Identifiers", style="cyan")
                table.add_column("Data", style="green")

                flattened_data: dict = self.flatten_json(data, separator='.')

                for key, value in flattened_data.items():
                    value_str = str(value)
                    table.add_row(key, value_str)

                console = Console()
                console.print(table)

    def nmap_menu(self) -> None:
        try:
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
            self.option = input("Enter your choice: ")
            match self.option:
                case "1":
                    clearscr()
                    table0 = Table()
                    table0.add_column("Options", style="cyan")
                    table0.add_column("AI Available", style="green")
                    table0.add_row("1", "OpenAI")
                    table0.add_row("2", "Bard")
                    table0.add_row("3", "LLama2")
                    print(Panel(table0))
                    self.ai_set_choice = input("Enter AI of Choice: ")
                    match self.ai_set_choice:
                        case "1":
                            self.ai_set_args, self.ai_set = "openai", "openai"
                            self.akey_set = input("Enter OpenAI API: ")
                            print(Panel(f"API-Key Set: {self.akey_set}"))
                        case "2":
                            self.ai_set_args, self.ai_set = "bard", "bard"
                            self.bkey_set = input("Enter Bard AI API: ")
                            print(Panel(f"API-Key Set: {self.bkey_set}"))
                        case "3":
                            clearscr()
                            tablel = Table()
                            tablel.add_column("Options", style="cyan")
                            tablel.add_column("Llama Options", style="cyan")
                            tablel.add_row("1", "Llama Local")
                            tablel.add_row("2", "Llama RunPod")
                            print(tablel)
                            self.ai_set_choice = input("Enter AI of Choice: ")
                            self.ai_set_args = "llama"
                            self.ai_set = "llama"
                            if self.ai_set_choice == "1":
                                self.ai_set = "llama"
                                print(Panel("No Key needed"))
                                print(Panel("Selected LLama"))
                            elif self.ai_set_choice == "2":
                                self.ai_set = "llama-api"
                                self.llamaendpoint = input("Enter Runpod Endpoint ID: ")
                                self.llamakey = input("Enter Runpod API Key: ")
                                print(Panel(f"API-Key Set: {self.llamakey}"))
                                print(Panel(f"Runpod Endpoint Set: {self.llamaendpoint}"))
                    self.nmap_menu()
                case "2":
                    clearscr()
                    print(Panel("Set Target Hostname or IP"))
                    self.t = input("Enter Target: ")
                    print(Panel(f"Target Set: {self.t}"))
                    self.nmap_menu()
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
                    self.profile_num = input("Enter your Profile: ")
                    print(Panel(f"Profile Set {self.profile_num}"))
                    self.nmap_menu()
                case "4":
                    clearscr()
                    table2 = Table()
                    table2.add_column("Options", style="cyan")
                    table2.add_column("Value", style="green")
                    table2.add_row("AI Set", str(self.ai_set_args))
                    table2.add_row("OpenAI API Key", str(self.akey_set))
                    table2.add_row("Bard AI API Key", str(self.bkey_set))
                    table2.add_row("Llama Runpod API Key", str(self.llamakey))
                    table2.add_row("Runpod Endpoint ID", str(self.llamaendpoint))
                    table2.add_row("Target", str(self.t))
                    table2.add_row("Profile", str(self.profile_num))
                    print(Panel(table2))
                    self.nmap_menu()
                case "5":
                    clearscr()
                    pout: str = port_scanner.scanner(
                        AIModels=p_ai_models,
                        ip=self.t,
                        profile=int(self.profile_num),
                        akey=self.akey_set,
                        bkey=self.bkey_set,
                        lkey=self.lkey,
                        lendpoint=self.lendpoint,
                        AI=self.ai_set
                    )
                    self.print_output("Nmap", pout, self.ai_set)
                case "r":
                    clearscr()
                    self.menu_term()
        except KeyboardInterrupt:
            print(Panel("Exiting Program"))

    def dns_menu(self) -> None:
        try:
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
                    table0.add_row("3", "LLama2")
                    print(Panel(table0))
                    self.ai_set_choice = input("Enter AI of Choice: ")
                    match self.ai_set_choice:
                        case "1":
                            self.ai_set_args, self.ai_set = "openai", "openai"
                            self.akey_set = input("Enter OpenAI API: ")
                            print(Panel(f"API-Key Set: {self.akey_set}"))
                        case "2":
                            self.ai_set_args, self.ai_set = "bard", "bard"
                            self.bkey_set = input("Enter Bard AI API: ")
                            print(Panel(f"API-Key Set: {self.bkey_set}"))
                        case "3":
                            clearscr()
                            tablel = Table()
                            tablel.add_column("Options", style="cyan")
                            tablel.add_column("Llama Options", style="cyan")
                            tablel.add_row("1", "Llama Local")
                            tablel.add_row("2", "Llama RunPod")
                            print(tablel)
                            self.ai_set_choice = input("Enter AI of Choice: ")
                            self.ai_set_args = "llama"
                            self.ai_set = "llama"
                            if self.ai_set_choice == "1":
                                self.ai_set = "llama"
                                print(Panel("No Key needed"))
                                print(Panel("Selected LLama"))
                            elif self.ai_set_choice == "2":
                                self.ai_set = "llama-api"
                                self.llamaendpoint = input("Enter Runpod Endpoint ID: ")
                                self.llamakey = input("Enter Runpod API Key: ")
                                print(Panel(f"API-Key Set: {self.llamakey}"))
                                print(Panel(f"Runpod Endpoint Set: {self.llamaendpoint}"))
                    self.dns_menu()
                case "2":
                    clearscr()
                    print(Panel("Set Target Hostname or IP"))
                    self.t = input("Enter Target: ")
                    print(Panel(f"Target Set:{self.t}"))
                    self.dns_menu()
                case "3":
                    clearscr()
                    table1 = Table()
                    table1.add_column("Options", style="cyan")
                    table1.add_column("Value", style="green")
                    table1.add_row("AI Set", str(self.ai_set_args))
                    table1.add_row("OpenAI API Key", str(self.akey_set))
                    table1.add_row("Bard AI API Key", str(self.bkey_set))
                    table1.add_row("Llama Runpod API Key", str(self.llamakey))
                    table1.add_row("Runpod Endpoint ID", str(self.llamaendpoint))
                    table1.add_row("Target", str(self.t))
                    print(Panel(table1))
                    self.dns_menu()
                case "4":
                    clearscr()
                    dns_output: str = dns_enum.dns_resolver(
                        AIModels=dns_ai_models,
                        target=self.t,
                        akey=self.akey_set,
                        bkey=self.bkey_set,
                        lkey=self.lkey,
                        lendpoint=self.lendpoint,
                        AI=self.ai_set
                    )
                    self.print_output("DNS", dns_output, self.ai_set)
                case "r":
                    clearscr()
                    self.menu_term()
        except KeyboardInterrupt:
            print(Panel("Exiting Program"))

    def geo_menu(self) -> None:
        try:
            table = Table()
            table.add_column("Options", style="cyan")
            table.add_column("Utility", style="green")
            table.add_row("1", "ADD API Key")
            table.add_row("2", "Set Target")
            table.add_row("3", "Show options")
            table.add_row("4", "Run Attack")
            table.add_row("r", "Return")
            console.print(table)
            self.option = input("Enter your choice: ")
            match self.option:
                case "1":
                    clearscr()
                    self.keyset = input("Enter GEO-IP API: ")
                    print(Panel(f"GEOIP API Key Set: {self.keyset}"))
                    self.geo_menu()
                case "2":
                    clearscr()
                    print(Panel("Set Target Hostname or IP"))
                    self.t = input("Enter Target: ")
                    print(Panel(f"Target Set: {self.t}"))
                    self.geo_menu()
                case "3":
                    clearscr()
                    table1 = Table()
                    table1.add_column("Options", style="cyan")
                    table1.add_column("Value", style="green")
                    table1.add_row("API Key", str(self.keyset))
                    table1.add_row("Target", str(self.t))
                    print(Panel(table1))
                    self.geo_menu()
                case "4":
                    clearscr()
                    geo_output: str = geo_ip.geoip(self.keyset, self.t)
                    self.print_output("GeoIP", str(geo_output), ai="None")
                case "r":
                    clearscr()
                    self.menu_term()
        except KeyboardInterrupt:
            print(Panel("Exiting Program"))

    def sub_menu(self) -> None:
        try:
            table = Table()
            table.add_column("Options", style="cyan")
            table.add_column("Utility", style="green")
            table.add_row("1", "ADD Subdomain list")
            table.add_row("2", "Set Target")
            table.add_row("3", "Show options")
            table.add_row("4", "Run Attack")
            table.add_row("r", "Return")
            console.print(table)
            self.option = input("Enter your choice: ")
            match self.option:
                case "1":
                    clearscr()
                    print(Panel("Set TXT subdomain file location"))
                    self.list_loc = input("Enter List Location:  ")
                    print(Panel(f"Location Set: {self.list_loc}"))
                    self.sub_menu()
                case "2":
                    clearscr()
                    print(Panel("Set Target Hostname or IP"))
                    self.t = input("Enter Target: ")
                    print(Panel(f"Target Set: {self.t}"))
                    self.sub_menu()
                case "3":
                    clearscr()
                    table1 = Table()
                    table1.add_column("Options", style="cyan")
                    table1.add_column("Value", style="green")
                    table1.add_row("Location", str(self.list_loc))
                    table1.add_row("Target", str(self.t))
                    print(Panel(table1))
                    self.sub_menu()
                case "4":
                    clearscr()
                    sub_output: str = sub_recon.sub_enumerator(self.t, self.list_loc)
                    console.print(sub_output, style="bold underline")
                case "r":
                    clearscr()
                    self.menu_term()
        except KeyboardInterrupt:
            print(Panel("Exiting Program"))

    def __init__(self, lkey, lendpoint, keyset, t, profile_num, ai_set, akey_set, bkey_set, ai_set_args, llamakey, llamaendpoint) -> None:
        try:
            self.lkey = lkey
            self.lendpoint = lendpoint
            self.keyset = keyset
            self.t = t
            self.profile_num = profile_num
            self.ai_set = ai_set
            self.akey_set = akey_set
            self.bkey_set = bkey_set
            self.ai_set_args = ai_set_args
            self.llamakey = llamakey
            self.llamaendpoint = llamaendpoint
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
                    self.nmap_menu()
                case "2":
                    clearscr()
                    self.dns_menu()
                case "3":
                    clearscr()
                    self.sub_menu()
                case "4":
                    clearscr()
                    self.geo_menu()
                case "q":
                    quit()
        except KeyboardInterrupt:
            print(Panel("Exiting Program"))
