import os
import sys
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.live import Live
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.rule import Rule
from rich import box


ACCENT = "green"
DIM = "bright_black"
WARN = "yellow"
ERR = "red"
INFO = "cyan"
KEY_COLOR = "bold green"

BANNER_ART = """[bold green]
   █████  ██    ██ ████████  ██████  ██     ██ ██ ███████ ██
  ██   ██ ██    ██    ██    ██    ██ ██     ██ ██ ██      ██
  ███████ ██    ██    ██    ██    ██ ██  █  ██ ██ █████   ██
  ██   ██ ██    ██    ██    ██    ██ ██ ███ ██ ██ ██      ██
  ██   ██  ██████     ██     ██████   ███ ███  ██ ██      ██
[/bold green]"""


class Display:
    def __init__(self):
        self.console = Console()
        self._width = min(self.console.width, 100)

    def clear(self):
        os.system("clear" if os.name == "posix" else "cls")

    def banner(self, version="2.0.0"):
        self.console.print(BANNER_ART, justify="center")
        self.console.print(
            f"  [dim]v{version}[/] [bright_black]|[/] [dim]Wireless Penetration Testing Framework[/]",
            justify="center",
        )
        self.console.print(
            f"  [bright_black]{'─' * 52}[/]",
            justify="center",
        )
        self.console.print()

    def status_bar(self, interface=None, mode=None, target=None, session=None):
        parts = []
        if interface:
            mode_color = ACCENT if mode == "Monitor" else WARN
            parts.append(f"[{DIM}]iface:[/] [{mode_color}]{interface}[/] [{DIM}]({mode})[/]")
        else:
            parts.append(f"[{ERR}]no interface selected[/]")

        if target:
            parts.append(f"[{DIM}]target:[/] [{ACCENT}]{target}[/]")

        if session:
            parts.append(f"[{DIM}]session:[/] [{INFO}]{session}[/]")

        bar_text = "  [bright_black]|[/]  ".join(parts)
        self.console.print(Panel(
            bar_text,
            border_style="bright_black",
            padding=(0, 1),
        ))

    def main_menu(self):
        menu_items = [
            ("1", "Select Interface", "choose wireless adapter"),
            ("2", "Scan Networks", "discover targets"),
            ("3", "Select Target", "pick attack target"),
            ("4", "Launch Attack", "run exploit chain"),
            ("5", "Crack Password", "dictionary / brute force"),
            ("6", "WPS Attack", "pixie dust / pin brute"),
            ("7", "PMKID Capture", "clientless attack"),
            ("8", "Sessions", "save / restore progress"),
            ("9", "Generate Report", "export findings"),
            ("s", "Settings", "configure framework"),
            ("d", "Dependencies", "check installed tools"),
            ("0", "Exit", "cleanup and quit"),
        ]

        self.console.print()
        for num, name, desc in menu_items:
            self.console.print(
                f"  [{ACCENT}][{num}][/]  {name}  [{DIM}]{desc}[/]"
            )
        self.console.print()

        return self.prompt("select", default="0")

    def network_table(self, networks, title="Discovered Networks"):
        table = Table(
            title=f"[bold {ACCENT}]{title}[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_black",
            title_style=f"bold {ACCENT}",
            header_style=f"bold {INFO}",
            show_lines=False,
            padding=(0, 1),
        )

        table.add_column("#", style="bold white", width=4, justify="right")
        table.add_column("BSSID", style="white", width=19)
        table.add_column("ESSID", style=f"bold {ACCENT}", max_width=24)
        table.add_column("CH", style="white", width=4, justify="center")
        table.add_column("ENC", width=10)
        table.add_column("AUTH", style=DIM, width=6)
        table.add_column("PWR", width=6, justify="right")
        table.add_column("SIGNAL", width=7)
        table.add_column("CLIENTS", width=8, justify="center")
        table.add_column("DATA", style=DIM, width=8, justify="right")

        for i, net in enumerate(networks, 1):
            enc = net.encryption.replace(" ", "")
            if "WPA2" in enc:
                enc_style = "yellow"
            elif "WPA" in enc:
                enc_style = "yellow"
            elif "WEP" in enc:
                enc_style = "red"
            elif "OPN" in enc:
                enc_style = "green"
            else:
                enc_style = "white"

            client_count = str(len(net.clients)) if net.clients else "-"
            client_style = f"bold {ACCENT}" if net.clients else DIM

            wps_indicator = " [magenta]WPS[/]" if net.wps else ""

            essid_display = net.essid if net.essid else "[dim]<hidden>[/]"

            table.add_row(
                str(i),
                net.bssid,
                essid_display,
                str(net.channel),
                f"[{enc_style}]{enc}[/]{wps_indicator}",
                net.auth,
                str(net.power),
                net.signal_bar,
                f"[{client_style}]{client_count}[/]",
                str(net.data_packets),
            )

        self.console.print(table)
        self.console.print(f"  [{DIM}]{len(networks)} networks found[/]")

    def client_table(self, clients, title="Connected Clients"):
        table = Table(
            title=f"[bold {INFO}]{title}[/]",
            box=box.SIMPLE,
            border_style="bright_black",
            header_style=f"bold {INFO}",
        )

        table.add_column("#", style="bold white", width=4, justify="right")
        table.add_column("MAC", style="white", width=19)
        table.add_column("AP BSSID", style=DIM, width=19)
        table.add_column("PWR", width=6, justify="right")
        table.add_column("PKTS", width=8, justify="right")
        table.add_column("PROBES", style=INFO, max_width=30)

        for i, client in enumerate(clients, 1):
            probes = ", ".join(client.probes[:3]) if client.probes else "-"
            table.add_row(
                str(i),
                client.mac,
                client.bssid if client.bssid else "-",
                str(client.power),
                str(client.packets),
                probes,
            )

        self.console.print(table)

    def interface_table(self, interfaces):
        table = Table(
            title=f"[bold {ACCENT}]Wireless Interfaces[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_black",
            header_style=f"bold {INFO}",
        )

        table.add_column("#", style="bold white", width=4, justify="right")
        table.add_column("Interface", style=f"bold {ACCENT}", width=14)
        table.add_column("Mode", width=10)
        table.add_column("MAC", style="white", width=19)
        table.add_column("Driver", style=DIM, width=16)
        table.add_column("Chipset", style=DIM, max_width=30)

        for i, iface in enumerate(interfaces, 1):
            mode_style = ACCENT if iface.mode == "Monitor" else "white"
            table.add_row(
                str(i),
                iface.name,
                f"[{mode_style}]{iface.mode}[/]",
                iface.mac,
                iface.driver,
                iface.chipset,
            )

        self.console.print(table)

    def attack_menu(self, attacks):
        self.console.print(f"\n  [bold {ACCENT}]Available Attack Vectors[/]\n")
        for i, (atype, name, desc) in enumerate(attacks, 1):
            self.console.print(f"  [{ACCENT}][{i}][/]  {name}  [{DIM}]{desc}[/]")
        self.console.print(f"  [{ERR}][0][/]  Back")
        self.console.print()

    def dependency_table(self, deps):
        table = Table(
            title=f"[bold {ACCENT}]Tool Dependencies[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_black",
            header_style=f"bold {INFO}",
        )

        table.add_column("Tool", style="white", width=18)
        table.add_column("Status", width=12, justify="center")
        table.add_column("Package / Purpose", style=DIM, max_width=35)

        for tool, (available, purpose) in sorted(deps.items()):
            status = f"[{ACCENT}]installed[/]" if available else f"[{ERR}]missing[/]"
            table.add_row(tool, status, purpose)

        self.console.print(table)

    def settings_table(self, config_data):
        table = Table(
            title=f"[bold {ACCENT}]Configuration[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_black",
            header_style=f"bold {INFO}",
        )

        table.add_column("#", style="bold white", width=4, justify="right")
        table.add_column("Setting", style="white", width=22)
        table.add_column("Value", style=ACCENT, max_width=40)

        for i, (key, value) in enumerate(config_data.items(), 1):
            table.add_row(str(i), key, str(value))

        self.console.print(table)

    def session_table(self, sessions):
        table = Table(
            title=f"[bold {ACCENT}]Saved Sessions[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_black",
            header_style=f"bold {INFO}",
        )

        table.add_column("#", style="bold white", width=4, justify="right")
        table.add_column("ID", style=INFO, width=22)
        table.add_column("Target", style=f"bold {ACCENT}", width=18)
        table.add_column("BSSID", style="white", width=19)
        table.add_column("Attack", style=DIM, width=12)
        table.add_column("Status", width=12, justify="center")

        for i, session in enumerate(sessions, 1):
            status = session.get("status", "unknown")
            if status == "completed":
                if session.get("key"):
                    status_display = f"[{ACCENT}]CRACKED[/]"
                else:
                    status_display = f"[{WARN}]done[/]"
            elif status == "failed":
                status_display = f"[{ERR}]failed[/]"
            else:
                status_display = f"[{INFO}]active[/]"

            table.add_row(
                str(i),
                session.get("id", "?")[:20],
                session.get("target_essid", "?"),
                session.get("target_bssid", "?"),
                session.get("attack_type", "?"),
                status_display,
            )

        self.console.print(table)

    def wordlist_table(self, wordlists):
        table = Table(
            title=f"[bold {ACCENT}]Available Wordlists[/]",
            box=box.SIMPLE,
            border_style="bright_black",
            header_style=f"bold {INFO}",
        )

        table.add_column("#", style="bold white", width=4, justify="right")
        table.add_column("Path", style="white", max_width=60)
        table.add_column("Size", style=INFO, width=12, justify="right")

        for i, (path, size) in enumerate(wordlists, 1):
            if size > 1024 * 1024 * 1024:
                size_str = f"{size / (1024**3):.1f} GB"
            elif size > 1024 * 1024:
                size_str = f"{size / (1024**2):.1f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"
            table.add_row(str(i), path, size_str)

        self.console.print(table)

    def success(self, msg):
        self.console.print(f"  [{ACCENT}][+][/] {msg}")

    def error(self, msg):
        self.console.print(f"  [{ERR}][-][/] {msg}")

    def warning(self, msg):
        self.console.print(f"  [{WARN}][!][/] {msg}")

    def info(self, msg):
        self.console.print(f"  [{INFO}][*][/] {msg}")

    def key_found(self, key, essid=""):
        self.console.print()
        border = "=" * 50
        self.console.print(f"  [{ACCENT}]{border}[/]")
        self.console.print(f"  [{ACCENT}]  KEY FOUND[/]")
        if essid:
            self.console.print(f"  [{DIM}]  Network: {essid}[/]")
        self.console.print(f"  [{KEY_COLOR}]  {key}[/]")
        self.console.print(f"  [{ACCENT}]{border}[/]")
        self.console.print()

    def attack_status(self, attack_name, status, elapsed=0):
        elapsed_str = f"{elapsed:.0f}s" if elapsed else ""
        self.console.print(
            f"  [{INFO}][>][/] {attack_name}  [{DIM}]{status}[/]  [{WARN}]{elapsed_str}[/]"
        )

    def progress_context(self, description="Working"):
        return Progress(
            SpinnerColumn(style=ACCENT),
            TextColumn(f"[{INFO}]{{task.description}}[/]"),
            BarColumn(bar_width=30, style=DIM, complete_style=ACCENT),
            TextColumn(f"[{DIM}]{{task.percentage:>3.0f}}%[/]"),
            TimeElapsedColumn(),
            console=self.console,
        )

    def spinner_context(self, description="Working"):
        return Progress(
            SpinnerColumn(style=ACCENT),
            TextColumn(f"[{INFO}]{{task.description}}[/]"),
            TimeElapsedColumn(),
            console=self.console,
        )

    def prompt(self, label="", default="", password=False):
        try:
            style = f"bold {ACCENT}"
            result = self.console.input(f"  [{style}]{label}>[/] ")
            return result.strip() or default
        except (EOFError, KeyboardInterrupt):
            return default

    def prompt_int(self, label="", default=0, min_val=None, max_val=None):
        while True:
            raw = self.prompt(label, str(default))
            try:
                val = int(raw)
                if min_val is not None and val < min_val:
                    self.error(f"minimum value: {min_val}")
                    continue
                if max_val is not None and val > max_val:
                    self.error(f"maximum value: {max_val}")
                    continue
                return val
            except ValueError:
                self.error("enter a number")

    def confirm(self, msg, default=False):
        suffix = "[Y/n]" if default else "[y/N]"
        result = self.prompt(f"{msg} {suffix}")
        if not result:
            return default
        return result.lower() in ("y", "yes")

    def separator(self):
        self.console.print(f"  [{DIM}]{'─' * 52}[/]")

    def wait_key(self, msg="press enter to continue"):
        self.prompt(f"[{DIM}]{msg}[/]")
