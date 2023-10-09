import json
import os
import platform
import subprocess
from typing import Any
from rich import print
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.console import Group
from rich.align import Align
from rich import box
from rich.markdown import Markdown

console = Console()


class Assets():
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
        CREATE_NEW_CONSOLE = 0x00000010
        osp = platform.system()
        match osp:
            case 'Darwin':
                subprocess.Popen(["python3", "llama_api.py"], creationflags=CREATE_NEW_CONSOLE)
            case 'Linux':
                subprocess.Popen(["python3", "llama_api.py"])
            case 'Windows':
                subprocess.Popen(["python", "llama_api.py"], creationflags=CREATE_NEW_CONSOLE)

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
