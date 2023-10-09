import dns.resolver
from rich.console import Console
from rich.progress import track
from rich.table import Table

console = Console()


class sub_enum():
    def display_urls(sd_data: list[str], count: int) -> None:
        console = Console()
        table = Table(title=f"GVA Subdomain report. found out of {count}", show_header=True, header_style="bold")
        table.add_column("Index", justify="right", style="cyan")
        table.add_column("URL", style="green")
        for index, url in enumerate(sd_data):
            table.add_row(str(index), url)
        console.print(table)

    def sub_enumerator(self, target: str, list: str) -> str:
        sd_data = []
        s_array = []
        count: int = 0
        with open(list, "r") as file:
            for line in file:
                subdomain_key = line.strip()
                s_array.append(subdomain_key)
        for subd in track(s_array):
            try:
                ip_value = dns.resolver.resolve(f'{subd}.{target}', 'A')
                if ip_value:
                    sd_data.append(f'{subd}.{target}')
                    if f"{subd}.{target}" in sd_data:
                        count = count + 1
                    else:
                        pass
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except KeyboardInterrupt:
                print('Ended')
                quit()
        self.display_urls(sd_data, count)
        return 'Done'
