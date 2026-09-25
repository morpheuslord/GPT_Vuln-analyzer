"""GVA — desktop GUI.

A customtkinter front-end for the GVA toolkit. Scans run on a background thread
so the window never freezes, results render into a scrollable console-style
panel, and the sidebar shows which AI providers actually have credentials.
"""
import json
import os
import threading

import customtkinter
from dotenv import load_dotenv

from GVA.ai_providers import (
    AIEngine,
    AnalysisReport,
    PROVIDER_CLASSES,
    config_from_keys,
    normalize_selection,
)
from GVA.dns_recon import DNSRecon
from GVA.geo import geo_ip_recon
from GVA.jwt import JWTAnalyzer
from GVA.packet_analysis import PacketAnalysis
from GVA.port_scanner import DEFAULT_PROFILE, NetworkScanner, get_profile, profile_choices
from GVA.subdomain import SubEnum

DEFAULT_LIST_LOC = "lists/default.txt"
DEFAULT_PCAP_OUT = "outputs/output.json"

load_dotenv()
GEOIP_KEY = os.getenv("GEOIP_API_KEY")

# --- backend singletons ------------------------------------------------------
dns_enum = DNSRecon()
geo_ip = geo_ip_recon()
packet_analysis = PacketAnalysis()
port_scanner = NetworkScanner()
jwt_analyzer = JWTAnalyzer()
sub_recon = SubEnum()

AI_CONFIG = config_from_keys(
    openai_key=os.getenv("OPENAI_API_KEY"),
    anthropic_key=os.getenv("ANTHROPIC_API_KEY"),
    gemini_key=os.getenv("GEMINI_API_KEY") or os.getenv("BARD_API_KEY"),
)
engine = AIEngine(AI_CONFIG)

AI_PROVIDER_CHOICES = [*PROVIDER_CLASSES, "all"]


def provider_configured(key: str) -> bool:
    """True when a provider is ready to use (has a key, or needs none)."""
    info = PROVIDER_CLASSES.get(key)
    if info is None or not info.needs_key:
        return True
    return bool(AI_CONFIG.get(key, {}).get("api_key"))


def default_provider() -> str:
    """First configured provider, so the AI selector works out of the box."""
    for key in PROVIDER_CLASSES:
        if provider_configured(key):
            return key
    return next(iter(PROVIDER_CLASSES))


# Declarative form spec per attack. `extra` is an optional second text field.
ATTACKS = {
    "nmap": {
        "title": "Nmap Scan",
        "blurb": "Scan a host for open ports and services, then let the AI read the output for weaknesses.",
        "target": ("Target", "IP address or hostname"),
        "ai": True,
        "profile": True,  # rendered as a dropdown of named nmap profiles
        "extra": None,
    },
    "dns": {
        "title": "DNS Recon",
        "blurb": "Pull DNS, reverse-DNS and zone-transfer records for a domain and hand them to the AI.",
        "target": ("Domain", "example.com"),
        "ai": True,
        "extra": None,
    },
    "sub": {
        "title": "Subdomain Enumeration",
        "blurb": "Check a wordlist of subdomains against a domain. The matches print in your terminal.",
        "target": ("Domain", "example.com"),
        "ai": False,
        "extra": ("Wordlist", DEFAULT_LIST_LOC, DEFAULT_LIST_LOC),
    },
    "jwt": {
        "title": "JWT Analysis",
        "blurb": "Decode a JWT and check it for the usual token attacks.",
        "target": ("JWT token", "eyJhbGciOi..."),
        "ai": True,
        "extra": None,
    },
    "pcap": {
        "title": "PCAP Analysis",
        "blurb": "Read a capture file for traffic, spoofing, and any credentials sent in the clear.",
        "target": ("Capture file", "path/to/capture.pcap"),
        "ai": False,
        "extra": ("Output JSON", DEFAULT_PCAP_OUT, DEFAULT_PCAP_OUT),
    },
    "geo": {
        "title": "GeoIP Recon",
        "blurb": "Look up where an IP address is, via ipgeolocation.io.",
        "target": ("IP address", "8.8.8.8"),
        "ai": False,
        "extra": None,
    },
}


def run_attack(attack: str, target: str, ai_selection: str, extra: str):
    """Execute a single attack and return its result (runs off the UI thread)."""
    providers = normalize_selection(ai_selection) if ai_selection else []
    if ATTACKS[attack]["ai"] and not providers:
        providers = [default_provider()]

    if attack == "geo":
        return geo_ip.geoip(GEOIP_KEY, target)
    if attack == "nmap":
        profile = int(extra) if extra and extra.strip().isdigit() else 1
        return port_scanner.scanner(target, profile, engine, providers)
    if attack == "dns":
        return dns_enum.dns_resolver(target, engine, providers)
    if attack == "sub":
        return sub_recon.sub_enumerator(target, extra or DEFAULT_LIST_LOC)
    if attack == "jwt":
        return jwt_analyzer.analyze(target, engine, providers)
    if attack == "pcap":
        packet_analysis.perform_full_analysis(pcap_path=target, json_path=extra or DEFAULT_PCAP_OUT)
        return "Done"
    raise ValueError(f"Unknown attack: {attack}")


def format_output(output) -> str:
    """Turn a backend result into displayable text (mirrors the old output_save)."""
    if output == "Done":
        return "Done. Results were written or printed to the terminal."
    if isinstance(output, AnalysisReport):
        display = {}
        if output.errors:
            display["errors"] = output.errors
        if output.consolidated is not None:
            display["consolidated"] = output.consolidated
            display["individual"] = output.individual
        elif output.individual:
            display.update(output.individual)
        elif not display:
            display["info"] = "No analysis was produced."
        return json.dumps(display, indent=2)
    try:
        return json.dumps(json.loads(output), indent=2)
    except (json.JSONDecodeError, TypeError):
        return str(output)


# --- palette -----------------------------------------------------------------
ACCENT = "#4f8cff"
ACCENT_HOVER = "#3b74e0"
APP_BG = "#0f1116"
SIDEBAR_BG = "#161922"
CARD_BG = "#1b1f29"
FIELD_BG = "#0f1218"
OK_GREEN = "#34d399"
RED = "#f87171"
MUTED = "#7d8595"
TEXT = "#e4e7ec"

# Fonts common on Linux; Tk falls back gracefully if a family is missing.
UI_FAMILY = "DejaVu Sans"
MONO_FAMILY = "DejaVu Sans Mono"

CONTENT_WIDTH = 860


class GVAApp(customtkinter.CTk):
    def __init__(self) -> None:
        super().__init__()
        customtkinter.set_appearance_mode("dark")

        self.title("GVA Vulnerability Analyzer")
        self.geometry("1120x740")
        self.minsize(940, 600)
        self.configure(fg_color=APP_BG)

        self.f_h1 = customtkinter.CTkFont(family=UI_FAMILY, size=23, weight="bold")
        self.f_ui = customtkinter.CTkFont(family=UI_FAMILY, size=14)
        self.f_ui_bold = customtkinter.CTkFont(family=UI_FAMILY, size=14, weight="bold")
        self.f_label = customtkinter.CTkFont(family=UI_FAMILY, size=11, weight="bold")
        self.f_small = customtkinter.CTkFont(family=UI_FAMILY, size=12)
        self.f_mono = customtkinter.CTkFont(family=MONO_FAMILY, size=13)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._nav_buttons: dict[str, customtkinter.CTkButton] = {}
        self._active: str | None = None
        self._running = False
        self._target_entry = None
        self._ai_selector = None
        self._extra_entry = None
        self._profile_selector = None
        self._profile_map: dict[str, int] = {}
        self._run_button = None

        self._build_sidebar()
        self._build_main()
        self._build_statusbar()

        self.select_attack("nmap")

    # ---------------------------------------------------------------- sidebar
    def _build_sidebar(self) -> None:
        bar = customtkinter.CTkFrame(self, width=248, corner_radius=0, fg_color=SIDEBAR_BG)
        bar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        bar.grid_propagate(False)
        bar.grid_rowconfigure(2, weight=1)

        customtkinter.CTkLabel(
            bar, text="GVA", font=customtkinter.CTkFont(family=UI_FAMILY, size=28, weight="bold"),
            text_color=TEXT,
        ).grid(row=0, column=0, padx=26, pady=(28, 0), sticky="w")
        customtkinter.CTkLabel(
            bar, text="Vulnerability Analyzer", text_color=MUTED, font=self.f_small,
        ).grid(row=1, column=0, padx=26, pady=(0, 20), sticky="w")

        nav = customtkinter.CTkFrame(bar, fg_color="transparent")
        nav.grid(row=2, column=0, padx=14, pady=4, sticky="new")
        for attack, spec in ATTACKS.items():
            btn = customtkinter.CTkButton(
                nav, text="   " + spec["title"], anchor="w", height=42,
                font=self.f_ui, fg_color="transparent", text_color="#c3c8d2",
                hover_color="#232733", corner_radius=9,
                command=lambda a=attack: self.select_attack(a),
            )
            btn.pack(fill="x", pady=3)
            self._nav_buttons[attack] = btn

        self._build_provider_status(bar)

    def _build_provider_status(self, parent) -> None:
        box = customtkinter.CTkFrame(parent, fg_color=CARD_BG, corner_radius=12)
        box.grid(row=3, column=0, padx=14, pady=18, sticky="sew")
        customtkinter.CTkLabel(
            box, text="AI PROVIDERS", text_color=MUTED, font=self.f_label,
        ).pack(anchor="w", padx=16, pady=(14, 8))
        for key, info in PROVIDER_CLASSES.items():
            ready = provider_configured(key)
            row = customtkinter.CTkFrame(box, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=2)
            customtkinter.CTkLabel(
                row, text="●" if ready else "○", width=14, font=self.f_small,
                text_color=OK_GREEN if ready else MUTED,
            ).pack(side="left")
            customtkinter.CTkLabel(
                row, text=info.label, text_color=TEXT if ready else MUTED, font=self.f_small,
            ).pack(side="left", padx=(6, 0))
        customtkinter.CTkLabel(
            box, text="Set the keys you want to use in the .env file.", text_color=MUTED, font=self.f_small,
        ).pack(anchor="w", padx=16, pady=(8, 14))

    # ------------------------------------------------------------------ main
    def _build_main(self) -> None:
        main = customtkinter.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew")
        # Centered, max-width content column so fields don't stretch edge-to-edge.
        main.grid_columnconfigure(0, weight=1)
        main.grid_columnconfigure(1, weight=0)
        main.grid_columnconfigure(2, weight=1)
        main.grid_rowconfigure(0, weight=1)

        content = customtkinter.CTkFrame(main, width=CONTENT_WIDTH, fg_color="transparent")
        content.grid(row=0, column=1, sticky="ns", pady=(30, 16))
        content.grid_propagate(False)
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(2, weight=1)

        # Header
        head = customtkinter.CTkFrame(content, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew")
        head.grid_columnconfigure(0, weight=1)
        self._title_label = customtkinter.CTkLabel(head, text="", anchor="w", font=self.f_h1, text_color=TEXT)
        self._title_label.grid(row=0, column=0, sticky="w")
        self._blurb_label = customtkinter.CTkLabel(head, text="", anchor="w", text_color=MUTED, font=self.f_small)
        self._blurb_label.grid(row=1, column=0, sticky="w", pady=(3, 0))

        # Input form card (contents rebuilt per attack)
        self._form = customtkinter.CTkFrame(content, fg_color=CARD_BG, corner_radius=14)
        self._form.grid(row=1, column=0, sticky="ew", pady=20)
        self._form.grid_columnconfigure(0, weight=1)

        # Output card
        out = customtkinter.CTkFrame(content, fg_color=CARD_BG, corner_radius=14)
        out.grid(row=2, column=0, sticky="nsew")
        out.grid_columnconfigure(0, weight=1)
        out.grid_rowconfigure(1, weight=1)

        toolbar = customtkinter.CTkFrame(out, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", padx=18, pady=(14, 0))
        toolbar.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(toolbar, text="OUTPUT", text_color=MUTED, font=self.f_label).grid(
            row=0, column=0, sticky="w")
        customtkinter.CTkButton(
            toolbar, text="Copy", width=62, height=28, font=self.f_small, fg_color="transparent",
            border_width=1, border_color="#333846", text_color="#c3c8d2", hover_color="#232733",
            corner_radius=8, command=self._copy_output,
        ).grid(row=0, column=1, padx=(6, 0))
        customtkinter.CTkButton(
            toolbar, text="Clear", width=62, height=28, font=self.f_small, fg_color="transparent",
            border_width=1, border_color="#333846", text_color="#c3c8d2", hover_color="#232733",
            corner_radius=8, command=self._clear_output,
        ).grid(row=0, column=2, padx=(6, 0))

        self.output_textbox = customtkinter.CTkTextbox(
            out, corner_radius=10, font=self.f_mono, fg_color=FIELD_BG, text_color=TEXT,
            wrap="word", border_width=0,
        )
        self.output_textbox.grid(row=1, column=0, sticky="nsew", padx=18, pady=16)
        self._set_output("Pick a scan on the left, enter a target, and hit Run.")

    def _build_statusbar(self) -> None:
        bar = customtkinter.CTkFrame(self, height=32, corner_radius=0, fg_color=SIDEBAR_BG)
        bar.grid(row=1, column=1, sticky="ew")
        bar.grid_propagate(False)
        self._status_dot = customtkinter.CTkLabel(bar, text="●", text_color=OK_GREEN, width=16, font=self.f_small)
        self._status_dot.pack(side="left", padx=(18, 2), pady=5)
        self._status_label = customtkinter.CTkLabel(bar, text="Ready", text_color=TEXT, font=self.f_small)
        self._status_label.pack(side="left", pady=5)

    # -------------------------------------------------------------- form build
    def _labeled_entry(self, label_text, placeholder="", value=""):
        wrap = customtkinter.CTkFrame(self._form, fg_color="transparent")
        wrap.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(
            wrap, text=label_text.upper(), font=self.f_label, text_color=MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", pady=(0, 5))
        entry = customtkinter.CTkEntry(
            wrap, placeholder_text=placeholder, height=42, font=self.f_ui,
            fg_color=FIELD_BG, border_color="#2b3140", border_width=1, corner_radius=9,
        )
        entry.grid(row=1, column=0, sticky="ew")
        if value:
            entry.insert(0, value)
        return wrap, entry

    def select_attack(self, attack: str) -> None:
        if self._running:
            return
        self._active = attack
        spec = ATTACKS[attack]

        for key, btn in self._nav_buttons.items():
            active = key == attack
            btn.configure(fg_color=ACCENT if active else "transparent",
                          text_color="#ffffff" if active else "#c3c8d2")

        self._title_label.configure(text=spec["title"])
        self._blurb_label.configure(text=spec["blurb"])

        for child in self._form.winfo_children():
            child.destroy()

        row = 0
        t_label, t_ph = spec["target"]
        wrap, self._target_entry = self._labeled_entry(t_label, t_ph)
        wrap.grid(row=row, column=0, sticky="ew", padx=22, pady=(22, 0))
        row += 1

        self._ai_selector = None
        if spec["ai"]:
            wrap = customtkinter.CTkFrame(self._form, fg_color="transparent")
            wrap.grid_columnconfigure(0, weight=1)
            customtkinter.CTkLabel(
                wrap, text="AI PROVIDER", font=self.f_label, text_color=MUTED, anchor="w",
            ).grid(row=0, column=0, sticky="w", pady=(0, 5))
            self._ai_selector = customtkinter.CTkOptionMenu(
                wrap, values=AI_PROVIDER_CHOICES, height=42, font=self.f_ui,
                fg_color=FIELD_BG, button_color=ACCENT, button_hover_color=ACCENT_HOVER,
                corner_radius=9, dropdown_font=self.f_ui,
            )
            self._ai_selector.set(default_provider())
            self._ai_selector.grid(row=1, column=0, sticky="ew")
            wrap.grid(row=row, column=0, sticky="ew", padx=22, pady=(16, 0))
            row += 1

        self._profile_selector = None
        self._profile_map = {}
        if spec.get("profile"):
            wrap = customtkinter.CTkFrame(self._form, fg_color="transparent")
            wrap.grid_columnconfigure(0, weight=1)
            customtkinter.CTkLabel(
                wrap, text="NMAP PROFILE", font=self.f_label, text_color=MUTED, anchor="w",
            ).grid(row=0, column=0, sticky="w", pady=(0, 5))
            profiles = profile_choices()
            self._profile_map = {p.label: p.number for p in profiles}
            self._profile_selector = customtkinter.CTkOptionMenu(
                wrap, values=[p.label for p in profiles], height=42, font=self.f_ui,
                fg_color=FIELD_BG, button_color=ACCENT, button_hover_color=ACCENT_HOVER,
                corner_radius=9, dropdown_font=self.f_small, command=self._on_profile_change,
            )
            self._profile_selector.set(get_profile(DEFAULT_PROFILE).label)
            self._profile_selector.grid(row=1, column=0, sticky="ew")
            self._profile_hint = customtkinter.CTkLabel(
                wrap, text="", font=self.f_small, text_color=MUTED, anchor="w", wraplength=560,
                justify="left",
            )
            self._profile_hint.grid(row=2, column=0, sticky="w", pady=(6, 0))
            wrap.grid(row=row, column=0, sticky="ew", padx=22, pady=(16, 0))
            self._on_profile_change(get_profile(DEFAULT_PROFILE).label)
            row += 1

        self._extra_entry = None
        if spec["extra"]:
            e_label, e_ph, e_val = spec["extra"]
            wrap, self._extra_entry = self._labeled_entry(e_label, e_ph, e_val)
            wrap.grid(row=row, column=0, sticky="ew", padx=22, pady=(16, 0))
            row += 1

        self._run_button = customtkinter.CTkButton(
            self._form, text="Run scan", height=46, font=self.f_ui_bold,
            fg_color=ACCENT, hover_color=ACCENT_HOVER, corner_radius=10, command=self._on_run,
        )
        self._run_button.grid(row=row, column=0, sticky="ew", padx=22, pady=22)
        self._target_entry.focus_set()

    # ------------------------------------------------------------------- run
    def _on_profile_change(self, label: str) -> None:
        prof = get_profile(self._profile_map.get(label, DEFAULT_PROFILE))
        note = prof.description
        if prof.needs_root:
            note += "  Needs root, so you'll be asked for a sudo password in the terminal."
        self._profile_hint.configure(text=note)

    def _on_run(self) -> None:
        if self._running:
            return
        target = self._target_entry.get().strip()
        if not target:
            self._set_status("A target is required.", "error")
            return

        ai_selection = self._ai_selector.get() if self._ai_selector else ""
        if self._profile_selector is not None:
            extra = str(self._profile_map.get(self._profile_selector.get(), DEFAULT_PROFILE))
        elif self._extra_entry is not None:
            extra = self._extra_entry.get().strip()
        else:
            extra = ""
        attack = self._active

        self._running = True
        self._run_button.configure(state="disabled", text="Running…")
        self._set_status(f"Running {ATTACKS[attack]['title']}…", "busy")
        self._set_output(f"Running {ATTACKS[attack]['title']} on “{target}” …\n")

        threading.Thread(
            target=self._worker, args=(attack, target, ai_selection, extra), daemon=True,
        ).start()

    def _worker(self, attack, target, ai_selection, extra) -> None:
        try:
            result = run_attack(attack, target, ai_selection, extra)
            self.after(0, lambda: self._finish(format_output(result), None))
        except Exception as exc:  # noqa: BLE001 - surface any backend failure
            self.after(0, lambda e=exc: self._finish(None, e))

    def _finish(self, text, error) -> None:
        self._running = False
        self._run_button.configure(state="normal", text="Run scan")
        if error is not None:
            self._set_output(f"Error:\n{error}")
            self._set_status(f"Failed: {error}", "error")
        else:
            self._set_output(text)
            self._set_status("Done", "ok")

    # --------------------------------------------------------------- helpers
    def _set_output(self, text: str) -> None:
        self.output_textbox.configure(state="normal")
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("1.0", text)

    def _clear_output(self) -> None:
        self._set_output("")
        self._set_status("Cleared", "ok")

    def _copy_output(self) -> None:
        text = self.output_textbox.get("1.0", "end").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._set_status("Output copied to clipboard", "ok")

    def _set_status(self, text: str, kind: str = "ok") -> None:
        colors = {"ok": OK_GREEN, "busy": ACCENT, "error": RED}
        self._status_dot.configure(text_color=colors.get(kind, OK_GREEN))
        self._status_label.configure(text=text)


def launch() -> None:
    GVAApp().mainloop()


if __name__ == "__main__":
    launch()
