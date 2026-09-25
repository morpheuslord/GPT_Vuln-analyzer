import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from rich.console import Console

from GVA.ai_providers import AIEngine, AnalysisReport

console = Console()

NMAP_HELP = (
    "nmap could not be run. Ensure the nmap program is installed and on PATH "
    "(and that its shared libraries load). See the README 'nmap' notes."
)

# nmap options that require raw-socket / root privileges.
PRIVILEGED_FLAGS = (
    '-O', '-A', '-sS', '-sU', '-sA', '-sW', '-sM', '-sN', '-sF', '-sX',
    '-sO', '-PE', '-PP', '-PM', '-PO',
)


@dataclass(frozen=True)
class NmapProfile:
    """A named, purpose-built nmap scan profile."""

    number: int
    name: str
    args: str
    description: str

    @property
    def needs_root(self) -> bool:
        tokens = self.args.split()
        return any(flag in tokens for flag in PRIVILEGED_FLAGS)

    @property
    def label(self) -> str:
        tag = "  (root)" if self.needs_root else ""
        return f"{self.number} · {self.name}{tag}"


# Curated, real-world profiles. 1–5 are unprivileged (TCP connect scans that run
# without root — safe defaults, and what the GUI can use out of the box); 6–10
# need root (SYN/UDP/OS fingerprinting) and are auto-escalated with sudo.
PROFILES: Dict[int, NmapProfile] = {
    1: NmapProfile(1, "Quick",
                   "-Pn -sT -sV -T4 --top-ports 100",
                   "Fast triage: top 100 TCP ports with service versions. No root."),
    2: NmapProfile(2, "Standard",
                   "-Pn -sT -sV -sC -T4 --top-ports 1000",
                   "Top 1000 ports with versions and default NSE scripts. No root."),
    3: NmapProfile(3, "Full TCP",
                   "-Pn -sT -sV -p- -T4",
                   "Every TCP port (1-65535) with versions. No root, slower."),
    4: NmapProfile(4, "Web services",
                   "-Pn -sT -sV -T4 -p 80,443,8080,8443,8000,8888,3000,5000 "
                   "--script=http-title,http-headers,http-methods,http-server-header",
                   "HTTP/S-focused scan of common web ports. No root."),
    5: NmapProfile(5, "Vulnerability",
                   "-Pn -sT -sV -T4 --script=vuln",
                   "NSE vulnerability scripts over versioned services. No root, slow."),
    6: NmapProfile(6, "Stealth SYN",
                   "-Pn -sS -sV -T4 --top-ports 1000",
                   "Half-open SYN scan of the top 1000 ports, quieter and faster. Root."),
    7: NmapProfile(7, "OS & service",
                   "-Pn -sS -sV -O -T4",
                   "SYN scan with OS fingerprinting and service detection. Root."),
    8: NmapProfile(8, "Aggressive",
                   "-Pn -A -T4",
                   "OS, versions, default scripts and traceroute in one pass. Root."),
    9: NmapProfile(9, "UDP top",
                   "-Pn -sU -sV -T4 --top-ports 50",
                   "Top 50 UDP services (DNS, SNMP, NTP…). Root, slow."),
    10: NmapProfile(10, "Deep audit",
                    "-Pn -sS -sV -O -p- -T4 --script=default,vuln",
                    "Full-port SYN scan with OS detection and vuln scripts. Root, very slow."),
}

DEFAULT_PROFILE = 1


def get_profile(profile: int) -> NmapProfile:
    """Return a profile, falling back to the default for unknown numbers."""
    return PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])


def profile_choices() -> List[NmapProfile]:
    """Profiles in display order, for CLI/GUI menus."""
    return [PROFILES[n] for n in sorted(PROFILES)]


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid() == 0 if geteuid else False


def _scan_is_empty(raw_scan: dict) -> bool:
    """True when nmap ran but reported no open ports on any host."""
    if not raw_scan:
        return True
    for host in raw_scan.values():
        for proto in ("tcp", "udp", "sctp"):
            ports = host.get(proto) if isinstance(host, dict) else None
            if ports and any(
                str(p.get("state", "")).startswith("open") for p in ports.values()
            ):
                return False
    return True


class NetworkScanner:
    # Kept as {number: args} for backward compatibility with older callers.
    profile_arguments = {n: p.args for n, p in PROFILES.items()}

    def _needs_root(self, arguments: str) -> bool:
        tokens = arguments.split()
        return any(flag in tokens for flag in PRIVILEGED_FLAGS)

    def scan_raw(self, ip: str, profile: int, sudo: bool = False) -> dict:
        # Imported lazily so the tool loads even without python-nmap installed.
        import nmap

        scanner = nmap.PortScanner()
        # sudo=True makes python-nmap run `sudo nmap ...`, which prompts for the
        # password on the terminal — only nmap is elevated, not the whole app.
        scanner.scan(ip, arguments=get_profile(profile).args, sudo=sudo)
        return scanner.analyse_nmap_xml_scan()["scan"]

    def scanner(self, ip: Optional[str], profile: int, engine: AIEngine,
                providers: Iterable[str], sudo: bool = False) -> AnalysisReport:
        prof = get_profile(profile)
        use_sudo = sudo or (prof.needs_root and not _is_root())
        if use_sudo:
            console.print(
                "[yellow]This nmap profile needs root, so GVA is escalating just the "
                "nmap step with sudo. You may be prompted for your password.[/yellow]"
            )
        console.print(
            f"[cyan]Running nmap scan on {ip}, profile {prof.number} "
            f"({prof.name}: {prof.args})…[/cyan]"
        )
        try:
            raw_scan = self.scan_raw(ip, profile, sudo=use_sudo)
        except Exception as exc:  # nmap missing/broken, or python-nmap not installed
            return AnalysisReport(scan_type="nmap", errors={"nmap": f"{NMAP_HELP}\n({exc})"})

        if _scan_is_empty(raw_scan):
            hint = (
                "run with sudo for OS detection" if prof.needs_root
                else "try a fuller profile such as 3 (full TCP) or 2 (standard)"
            )
            return AnalysisReport(scan_type="nmap", errors={"nmap": (
                f"nmap completed but found no open ports on {ip} using profile "
                f"{prof.number} ({prof.name}). The host may be down, firewalled, or "
                f"the scanned range may not cover its services, so {hint}."
            )})
        return engine.run("nmap", str(raw_scan), providers)
