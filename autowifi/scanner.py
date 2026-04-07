import subprocess
import csv
import time
import os
import re
import signal
import tempfile
from dataclasses import dataclass, field
from threading import Thread, Event


@dataclass
class Client:
    mac: str
    bssid: str
    power: int
    packets: int = 0
    probes: list = field(default_factory=list)


@dataclass
class Network:
    bssid: str
    essid: str
    channel: int
    encryption: str
    cipher: str
    auth: str
    power: int
    beacons: int
    data_packets: int
    wps: bool = False
    wps_version: str = ""
    wps_locked: bool = False
    clients: list = field(default_factory=list)

    @property
    def enc_display(self):
        if "WPA2" in self.encryption and "WPA" in self.encryption:
            return "WPA/WPA2"
        if "WPA2WPA" in self.encryption:
            return "WPA/WPA2"
        return self.encryption.replace(" ", "")

    @property
    def signal_quality(self):
        if self.power >= -50:
            return "Excellent"
        if self.power >= -60:
            return "Good"
        if self.power >= -70:
            return "Fair"
        if self.power >= -80:
            return "Weak"
        return "Poor"

    @property
    def signal_bar(self):
        if self.power >= -50:
            return "[green]" + "|" * 5 + "[/]"
        if self.power >= -60:
            return "[green]" + "|" * 4 + "[/][dim]|[/]"
        if self.power >= -70:
            return "[yellow]" + "|" * 3 + "[/][dim]||[/]"
        if self.power >= -80:
            return "[red]" + "|" * 2 + "[/][dim]|||[/]"
        return "[red]|[/][dim]||||[/]"

    @property
    def is_wep(self):
        return "WEP" in self.encryption

    @property
    def is_wpa(self):
        return "WPA" in self.encryption

    @property
    def is_open(self):
        return "OPN" in self.encryption or self.encryption.strip() == ""

    @property
    def client_count(self):
        return len(self.clients)


class NetworkScanner:
    def __init__(self, interface):
        self.interface = interface
        self._process = None
        self._stop_event = Event()
        self.networks = []
        self.clients = []
        self._tmpdir = None

    def scan(self, duration=30, channel=None):
        self._tmpdir = tempfile.mkdtemp(prefix="awf_")
        prefix = os.path.join(self._tmpdir, "scan")

        cmd = [
            "airodump-ng",
            "--write", prefix,
            "--write-interval", "2",
            "--output-format", "csv",
            "--band", "abg",
        ]

        if channel:
            cmd.extend(["--channel", str(channel)])
        cmd.append(self.interface)

        self._process = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        self._stop_event.clear()
        csv_file = prefix + "-01.csv"

        start = time.time()
        while time.time() - start < duration and not self._stop_event.is_set():
            time.sleep(2)
            if os.path.exists(csv_file):
                self._parse_csv(csv_file)

        self.stop()
        if os.path.exists(csv_file):
            self._parse_csv(csv_file)

        return self.networks

    def start_live(self, callback, channel=None):
        self._tmpdir = tempfile.mkdtemp(prefix="awf_")
        prefix = os.path.join(self._tmpdir, "scan")

        cmd = [
            "airodump-ng",
            "--write", prefix,
            "--write-interval", "1",
            "--output-format", "csv",
            "--band", "abg",
        ]

        if channel:
            cmd.extend(["--channel", str(channel)])
        cmd.append(self.interface)

        self._process = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        self._stop_event.clear()
        csv_file = prefix + "-01.csv"

        def _monitor():
            while not self._stop_event.is_set():
                time.sleep(1)
                if os.path.exists(csv_file):
                    self._parse_csv(csv_file)
                    callback(self.networks, self.clients)

        thread = Thread(target=_monitor, daemon=True)
        thread.start()
        return thread

    def stop(self):
        self._stop_event.set()
        if self._process and self._process.poll() is None:
            self._process.send_signal(signal.SIGTERM)
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

    def _parse_csv(self, filepath):
        networks = []
        clients = []
        section = "networks"

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (IOError, OSError):
            return

        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue
            if "Station MAC" in line:
                section = "clients"
                continue
            if "BSSID" in line and "ESSID" in line:
                section = "networks"
                continue

            parts = [p.strip() for p in line.split(",")]

            if section == "networks" and len(parts) >= 14:
                bssid = parts[0]
                if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                    continue

                try:
                    power = int(parts[8].strip()) if parts[8].strip().lstrip("-").isdigit() else -100
                    channel = int(parts[3].strip()) if parts[3].strip().isdigit() else 0
                    beacons = int(parts[9].strip()) if parts[9].strip().isdigit() else 0
                    data = int(parts[10].strip()) if parts[10].strip().isdigit() else 0
                except (ValueError, IndexError):
                    continue

                if power == -1:
                    continue

                essid = parts[13].strip() if len(parts) > 13 else ""
                encryption = parts[5].strip() if len(parts) > 5 else ""
                cipher_val = parts[6].strip() if len(parts) > 6 else ""
                auth_val = parts[7].strip() if len(parts) > 7 else ""

                networks.append(Network(
                    bssid=bssid, essid=essid, channel=channel,
                    encryption=encryption, cipher=cipher_val, auth=auth_val,
                    power=power, beacons=beacons, data_packets=data,
                ))

            elif section == "clients" and len(parts) >= 6:
                sta_mac = parts[0]
                if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", sta_mac):
                    continue

                try:
                    sta_power = int(parts[3].strip()) if parts[3].strip().lstrip("-").isdigit() else -100
                    sta_packets = int(parts[4].strip()) if parts[4].strip().isdigit() else 0
                except (ValueError, IndexError):
                    sta_power = -100
                    sta_packets = 0

                sta_bssid = parts[5].strip() if len(parts) > 5 else ""
                probes_raw = parts[6].strip() if len(parts) > 6 else ""
                probes = [p.strip() for p in probes_raw.split(",") if p.strip()] if probes_raw else []

                clients.append(Client(
                    mac=sta_mac, bssid=sta_bssid,
                    power=sta_power, packets=sta_packets, probes=probes,
                ))

        for net in networks:
            net.clients = [c for c in clients if c.bssid == net.bssid]

        self.networks = sorted(networks, key=lambda n: n.power, reverse=True)
        self.clients = clients

    def scan_wps(self, duration=15):
        cmd = ["wash", "-i", self.interface]

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

        time.sleep(duration)
        proc.send_signal(signal.SIGTERM)
        try:
            stdout, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()

        wps_nets = []
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith("BSSID") or line.startswith("---") or line.startswith("Wash"):
                continue
            parts = line.split()
            if len(parts) >= 6:
                bssid = parts[0]
                if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                    continue
                ch = int(parts[1]) if parts[1].isdigit() else 0
                wps_ver = parts[3] if len(parts) > 3 else ""
                locked = parts[4].lower() in ("yes", "locked") if len(parts) > 4 else False
                essid = " ".join(parts[5:]) if len(parts) > 5 else ""

                wps_nets.append(Network(
                    bssid=bssid, essid=essid, channel=ch,
                    encryption="WPA", cipher="", auth="",
                    power=-50, beacons=0, data_packets=0,
                    wps=True, wps_version=wps_ver, wps_locked=locked,
                ))

        return wps_nets
