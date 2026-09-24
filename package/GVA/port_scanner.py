import os
from typing import Iterable, Optional

from rich.console import Console

from GVA.ai_providers import AIEngine, AnalysisReport

console = Console()

NMAP_HELP = (
    "nmap could not be run. Ensure the nmap program is installed and on PATH "
    "(and that its shared libraries load). See the README 'nmap' notes."
)

# nmap options that require raw-socket / root privileges.
PRIVILEGED_FLAGS = (
    '-O', '-sS', '-sU', '-sA', '-sW', '-sM', '-sN', '-sF', '-sX',
    '-sO', '-PE', '-PP', '-PM', '-PO',
)


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid() == 0 if geteuid else False


class NetworkScanner:
    profile_arguments = {
        1: '-Pn -sV -T4 -O -F',
        2: '-Pn -T4 -A -v',
        3: '-Pn -sS -sU -T4 -A -v',
        4: '-Pn -p- -T4 -A -v',
        5: '-Pn -sS -sU -T4 -A -PE -PP  -PY -g 53 --script=vuln',
        6: '-Pn -sV -p- -A',
        7: '-Pn -sS -sV -O -T4 -A',
        8: '-Pn -sC',
        9: '-Pn -p 1-65535 -T4 -A -v',
        10: '-Pn -sU -T4',
        11: '-Pn -sV --top-ports 100',
        12: '-Pn -sS -sV -T4 --script=default,discovery,vuln',
        13: '-Pn -F',
    }

    def _needs_root(self, arguments: str) -> bool:
        tokens = arguments.split()
        return any(flag in tokens for flag in PRIVILEGED_FLAGS)

    def scan_raw(self, ip: str, profile: int, sudo: bool = False) -> dict:
        # Imported lazily so the tool loads even without python-nmap installed.
        import nmap

        scanner = nmap.PortScanner()
        # sudo=True makes python-nmap run `sudo nmap ...`, which prompts for the
        # password on the terminal — only nmap is elevated, not the whole app.
        scanner.scan(
            ip,
            arguments=self.profile_arguments.get(profile, self.profile_arguments[1]),
            sudo=sudo,
        )
        return scanner.analyse_nmap_xml_scan()["scan"]

    def scanner(self, ip: Optional[str], profile: int, engine: AIEngine,
                providers: Iterable[str], sudo: bool = False) -> AnalysisReport:
        arguments = self.profile_arguments.get(profile, self.profile_arguments[1])
        use_sudo = sudo or (self._needs_root(arguments) and not _is_root())
        if use_sudo:
            console.print(
                "[yellow]This nmap profile needs root privileges — escalating just the "
                "nmap step with sudo. You may be prompted for your password.[/yellow]"
            )
        console.print(f"[cyan]Running nmap scan on {ip} (profile {profile})…[/cyan]")
        try:
            raw_scan = self.scan_raw(ip, profile, sudo=use_sudo)
        except Exception as exc:  # nmap missing/broken, or python-nmap not installed
            return AnalysisReport(scan_type="nmap", errors={"nmap": f"{NMAP_HELP}\n({exc})"})
        return engine.run("nmap", str(raw_scan), providers)
