import os
import platform
from rich import print
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from components.dns_recon import DNSRecon
from components.geo import geo_ip_recon
from components.port_scanner import NetworkScanner
from components.jwt import JWTAnalyzer
from components.packet_analysis import PacketAnalysis
from components.models import NMAP_AI_MODEL
from components.models import DNS_AI_MODEL
from components.models import JWT_AI_MODEL
from components.subdomain import SubEnum
from components.assets import Assets
from components.passbeaker import PasswordCracker

assets = Assets()
dns_enum = DNSRecon()
geo_ip = geo_ip_recon()
packetanalysis = PacketAnalysis()
jwt_analyzer = JWTAnalyzer()
p_ai_models = NMAP_AI_MODEL()
dns_ai_models = DNS_AI_MODEL()
jwt_ai_model = JWT_AI_MODEL()
port_scanner = NetworkScanner()
sub_recon = SubEnum()
console = Console()


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
            table.add_row("q", "Quit")
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
                    table1.add_row("6", "-Pn -sV -p- -A")
                    table1.add_row("7", "-Pn -sS -sV -O -T4 -A")
                    table1.add_row("8", "-Pn -sC")
                    table1.add_row("9", "-Pn -p 1-65535 -T4 -A -v")
                    table1.add_row("10", "-Pn -sU -T4")
                    table1.add_row("11", "-Pn -sV --top-ports 100")
                    table1.add_row("12", "-Pn -sS -sV -T4 --script=default,discovery,vuln")
                    table1.add_row("13", "-Pn -F")
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
                    assets.print_output("Nmap", pout, self.ai_set)
                case "q":
                    quit()
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
            table.add_row("q", "Quit")
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
                    assets.print_output("DNS", dns_output, self.ai_set)
                case "q":
                    quit()
        except KeyboardInterrupt:
            print(Panel("Exiting Program"))

    def jwt_menu(self) -> None:
        try:
            table = Table()
            table.add_column("Options", style="cyan")
            table.add_column("Utility", style="green")
            table.add_row("1", "AI Option")
            table.add_row("2", "Set Token")
            table.add_row("3", "Show options")
            table.add_row("4", "Run Attack")
            table.add_row("q", "Quit")
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
                    self.jwt_menu()
                case "2":
                    clearscr()
                    print(Panel("Set Token value"))
                    self.t = input("Enter TOKEN: ")
                    print(Panel(f"Token Set:{self.t}"))
                    self.jwt_menu()
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
                    table1.add_row("JWT TOKEN", str(self.t))
                    print(Panel(table1))
                    self.jwt_menu()
                case "4":
                    clearscr()
                    JWT_output: str = jwt_analyzer.analyze(
                        AIModels=jwt_ai_model,
                        token=self.t,
                        openai_api_token=self.akey_set,
                        bard_api_token=self.bkey_set,
                        llama_api_token=self.lkey,
                        llama_endpoint=self.lendpoint,
                        AI=self.ai_set
                    )
                    assets.print_output("JWT", JWT_output, self.ai_set)
                case "q":
                    quit()
        except KeyboardInterrupt:
            print(Panel("Exiting Program"))

    def pcap_menu(self) -> None:
        try:
            table = Table()
            table.add_column("Options", style="cyan")
            table.add_column("Utility", style="green")
            table.add_row("1", "Set Target file location")
            table.add_row("2", "Set Output file location")
            table.add_row("3", "Show options")
            table.add_row("4", "Run Attack")
            table.add_row("q", "Quit")
            console.print(table)
            self.option = input("Enter your choice: ")
            match self.option:
                case "1":
                    clearscr()
                    print(Panel("Set Target PCAP file Location"))
                    self.t = input("Enter Target: ")
                    print(Panel(f"Target Set: {self.t}"))
                    self.pcap_menu()
                case "2":
                    clearscr()
                    print(Panel("Set Output file Location"))
                    self.t = input("Enter Location: ")
                    print(Panel(f"Output Set: {self.output_loc}"))
                    self.pcap_menu()
                case "3":
                    clearscr()
                    print(Panel("Set Number of threads"))
                    self.t = input("Enter Threads: ")
                    print(Panel(f"Threads Set: {self.threads}"))
                    self.pcap_menu()
                case "4":
                    clearscr()
                    packetanalysis.perform_full_analysis(
                        pcap_path=self.t,
                        json_path=self.output_loc,
                    )
                case "q":
                    quit()
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
            table.add_row("q", "Quit")
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
                    assets.print_output("GeoIP", str(geo_output), ai="None")
                case "q":
                    quit()
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
            table.add_row("q", "Quit")
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
                case "q":
                    quit()
        except KeyboardInterrupt:
            print(Panel("Exiting Program"))

    def str_to_bool(self, input_str):
        return input_str.lower() in ('true', '1', 't', 'y', 'yes')

    def hash_menu(self) -> None:
        """
            Password Hash: str
            Salt: str
            Wordlist File: str:loc
            Algorithm: str
            Parallel Processing: bool: True
            Complexity: bool: True
            Min Length: int:1
            Max Length: int:6
            Charecter Set: str:abcdefghijklmnopqrstuvwxyz0123456789
            Bruteforce: bool:True
            Attack
            password_hash, salt, wordlist_loc, algorithm, parallel_proc, complexity, min_length, max_length, char_set, bforce
        """
        try:
            self.char_set = "abcdefghijklmnopqrstuvwxyz0123456789"
            self.min_length = 1
            self.max_length = 6
            table = Table()
            table.add_column("Options", style="cyan")
            table.add_column("Utility", style="green")
            table.add_row("1", "Set Password Hash")
            table.add_row("2", "Set Salt")
            table.add_row("3", "Set Algorithm")
            table.add_row("4", "Set Wordlist Loc")
            table.add_row("5", "Set Parallel Proc")
            table.add_row("6", "Set Complexity")
            table.add_row("7", "Set Min Gen Length")
            table.add_row("8", "Set Max Gen Length")
            table.add_row("9", "Set Charecter Set")
            table.add_row("10", "Set Attack Type")
            table.add_row("11", "Show Options")
            table.add_row("12", "Run Attack")
            table.add_row("q", "Quit")
            console.print(table)
            self.option = input("Enter your choice: ")
            match self.option:
                case "1":
                    clearscr()
                    print(Panel("Set Password Hash Value"))
                    self.password_hash = input("Enter Hash Value:  ")
                    print(Panel(f"Hash Set: {self.password_hash}"))
                    self.hash_menu()
                case "2":
                    clearscr()
                    print(Panel("Set Salt Value"))
                    self.salt = input("Enter Salt Value:  ")
                    print(Panel(f"Salt Set: {self.salt}"))
                    self.hash_menu()
                case "3":
                    clearscr()
                    print(Panel("""
                                Set Algorithm Value
                                Select From: sha256,shake_128,sha3_224,sha1,sha224,sha512,blake2s,blake2b,md5,sha384,sha3_384,sha3_256,shake_256,sha3_512
                                """))
                    self.algorithm = input("Enter Algorithm Value:  ")
                    print(Panel(f"Algorithm Set: {self.algorithm}"))
                    self.hash_menu()
                case "4":
                    clearscr()
                    print(Panel("Set Wordlist location"))
                    self.wordlist_loc = input("Enter Wordlist location:  ")
                    print(Panel(f"Wordlist Location Set: {self.wordlist_loc}"))
                    self.hash_menu()
                case "5":
                    clearscr()
                    print(Panel(f"Set Parallel Processing: Default value = {self.parallel_proc}"))
                    self.parallel_proc = self.str_to_bool(input("Enter True/False:  "))
                    print(Panel(f"Proccessing Option Set: {self.parallel_proc}"))
                    self.hash_menu()
                case "6":
                    clearscr()
                    print(Panel(f"Set Complexity: Default value = {self.complexity}"))
                    self.complexity = self.str_to_bool(input("Enter True/False:  "))
                    print(Panel(f"Complexity Set: {self.complexity}"))
                    self.hash_menu()
                case "7":
                    clearscr()
                    print(Panel(f"Set Min Password Gen value: Default value = {self.min_length}"))
                    self.min_length = input("Enter Number:  ")
                    print(Panel(f"Min value Set: {self.min_length}"))
                    self.hash_menu()
                case "8":
                    clearscr()
                    print(Panel(f"Set Max Password Gen value: Default value = {self.max_length}"))
                    self.max_length = input("Enter Number:  ")
                    print(Panel(f"Max Value Set: {self.max_length}"))
                    self.hash_menu()
                case "9":
                    clearscr()
                    print(Panel(f"Set Charecter Set value: Default value = {self.char_set}"))
                    self.max_length = input("Enter Number:  ")
                    print(Panel(f"Charecter Set: {self.max_length}"))
                    self.hash_menu()
                case "10":
                    clearscr()
                    print(Panel(f"Set Attack Type: Default value = {self.bforce}"))
                    self.bforce = self.str_to_bool(input("Enter True/False:  "))
                    print(Panel(f"Attack Type Set: {self.bforce}"))
                    self.hash_menu()
                case "11":
                    clearscr()
                    clearscr()
                    table1 = Table()
                    table1.add_column("Options", style="cyan")
                    table1.add_column("Value", style="green")
                    table1.add_row("Password hash", str(self.password_hash))
                    table1.add_row("Salt", str(self.salt))
                    table1.add_row("Algorithm", str(self.algorithm))
                    table1.add_row("Wordlist Loc", str(self.wordlist_loc))
                    table1.add_row("Parallel Proc", str(self.parallel_proc))
                    table1.add_row("Complexity", str(self.complexity))
                    table1.add_row("Min Gen Length", str(self.min_length))
                    table1.add_row("Max Gen Length", str(self.max_length))
                    table1.add_row("Charecter Set", str(self.char_set))
                    table1.add_row("Attack Type", str(self.bforce))
                    print(Panel(table1))
                    self.hash_menu()
                case "12":
                    clearscr()
                    self.parallel_proc = True if self.parallel_proc is None else self.parallel_proc
                    self.complexity = True if self.complexity is None else self.complexity
                    self.bforce = True if self.bforce is None else self.bforce
                    print(self.parallel_proc)
                    print(self.complexity)
                    print(self.bforce)
                    passcracker = PasswordCracker(
                        password_hash=self.password_hash,
                        wordlist_file=self.wordlist_loc,
                        algorithm=self.algorithm,
                        salt=self.salt,
                        parallel=self.parallel_proc,
                        complexity_check=self.complexity
                    )
                    if self.bforce is True:
                        passcracker.crack_passwords_with_brute_force(self.min_length, self.max_length, self.char_set)
                    elif self.bforce is False:
                        passcracker.crack_passwords_with_wordlist()
                    passcracker.print_statistics()
                case "q":
                    quit()
        except KeyboardInterrupt:
            print(Panel("Exiting Program"))

    def __init__(self, lkey, threads, output_loc, lendpoint, keyset, t, profile_num, ai_set, akey_set, bkey_set, ai_set_args, llamakey, llamaendpoint, password_hash, salt, wordlist_loc, algorithm, parallel_proc, complexity, min_length, max_length, char_set, bforce) -> None:
        try:
            self.lkey = lkey
            self.threads = threads
            self.output_loc = output_loc
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
            self.password_hash = password_hash
            self.salt = salt
            self.wordlist_loc = wordlist_loc
            self.algorithm = algorithm
            self.parallel_proc = parallel_proc
            self.complexity = complexity
            self.min_length = min_length
            self.max_length = max_length
            self.char_set = char_set
            self.bforce = bforce
            table = Table()
            table.add_column("Options", style="cyan")
            table.add_column("Utility", style="green")
            table.add_row("1", "Nmap Enum")
            table.add_row("2", "DNS Enum")
            table.add_row("3", "Subdomain Enum")
            table.add_row("4", "GEO-IP Enum")
            table.add_row("5", "JWT Analysis")
            table.add_row("6", "PCAP Analysis")
            table.add_row("7", "Hash Cracker")
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
                case "5":
                    clearscr()
                    self.jwt_menu()
                case "6":
                    clearscr()
                    self.pcap_menu()
                case "7":
                    clearscr()
                    self.hash_menu()
                case "q":
                    quit()
        except KeyboardInterrupt:
            print(Panel("Exiting Program"))
