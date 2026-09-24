import dns.resolver
from rich.console import Console
from rich.progress import track
from rich.table import Table


class SubEnum:
    @staticmethod
    def display_urls(sd_data: list[str], count: int) -> None:
        console = Console()
        table = Table(title=f"GVA Subdomain report. {count} found", show_header=True, header_style="bold")
        table.add_column("Index", justify="right", style="cyan")
        table.add_column("URL", style="green")
        for index, url in enumerate(sd_data):
            table.add_row(str(index), url)
        console.print(table)

    def sub_enumerator(self, target: str, list_file: str) -> str:
        with open(list_file, "r") as file:
            s_array = [line.strip() for line in file]

        sd_data = []
        for subd in track(s_array):
            try:
                if dns.resolver.resolve(f'{subd}.{target}', 'A'):
                    sd_data.append(f'{subd}.{target}')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except KeyboardInterrupt:
                print('Ended')
                quit()

        self.display_urls(sd_data, len(sd_data))
        return 'Done'
