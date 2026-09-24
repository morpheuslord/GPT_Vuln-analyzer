"""Live progress board for AI analysis runs.

Shows, in real time: which models are analysing, how long each took, and the
deliberation step — so the terminal isn't blank while models are thinking.

It is a plain reporter with no-op-safe methods; the AI engine calls them and
this class renders them with rich.Live. Used only for terminal runs.
"""
from __future__ import annotations

import time
from typing import Dict, Optional

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

console = Console()


class LiveScan:
    def __init__(self, title: str, con: Optional[Console] = None) -> None:
        self.title = title
        self.console = con or console
        self._phase: str = ""
        self._providers: Dict[str, dict] = {}
        self._delib: Optional[dict] = None
        self._live: Optional[Live] = None

    # ------------------------------------------------------------ lifecycle
    def __enter__(self) -> "LiveScan":
        self._live = Live(self._render(), console=self.console,
                          refresh_per_second=12, transient=True)
        self._live.__enter__()
        return self

    def __exit__(self, *exc) -> bool:
        if self._live:
            self._live.__exit__(*exc)
            self._live = None
        return False

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._render())

    # --------------------------------------------------------------- events
    def phase(self, text: str) -> None:
        self._phase = text
        self._refresh()

    def start_providers(self, labels: Dict[str, str]) -> None:
        now = time.monotonic()
        for key, label in labels.items():
            self._providers[key] = {"label": label, "state": "run", "start": now,
                                    "elapsed": 0.0, "error": None}
        self._phase = f"Analysing with {len(labels)} model(s)…"
        self._refresh()

    def provider_done(self, key: str, error: Optional[str] = None) -> None:
        p = self._providers.get(key)
        if not p:
            return
        p["elapsed"] = time.monotonic() - p["start"]
        p["state"] = "err" if error else "ok"
        p["error"] = error
        self._refresh()

    def start_deliberation(self, label: str) -> None:
        self._delib = {"label": label, "state": "run", "start": time.monotonic(),
                       "elapsed": 0.0, "error": None}
        self._phase = "Deliberating…"
        self._refresh()

    def deliberation_done(self, error: Optional[str] = None) -> None:
        if self._delib:
            self._delib["elapsed"] = time.monotonic() - self._delib["start"]
            self._delib["state"] = "err" if error else "ok"
            self._delib["error"] = error
        self._refresh()

    # -------------------------------------------------------------- render
    @staticmethod
    def _status_cell(p: dict):
        if p["state"] == "run":
            return Spinner("dots", text=Text(" analysing…", style="yellow"))
        if p["state"] == "ok":
            return Text(f"✓ done ({p['elapsed']:.1f}s)", style="green")
        return Text(f"✗ {str(p['error'])[:70]}", style="red")

    def _render(self):
        items = []
        if self._phase:
            items.append(Spinner("dots", text=Text(f" {self._phase}", style="bold cyan")))
        if self._providers:
            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_column("model", style="bold")
            table.add_column("status")
            for p in self._providers.values():
                table.add_row(p["label"], self._status_cell(p))
            items.append(table)
        if self._delib:
            d = self._delib
            if d["state"] == "run":
                items.append(Spinner("dots", text=Text(f" deliberating with {d['label']}…", style="magenta")))
            elif d["state"] == "ok":
                items.append(Text(f"✓ consolidated by {d['label']} ({d['elapsed']:.1f}s)", style="green"))
            else:
                items.append(Text(f"✗ deliberation failed: {d['error']}", style="red"))
        return Panel(Group(*items), title=self.title, border_style="blue", padding=(1, 2))
