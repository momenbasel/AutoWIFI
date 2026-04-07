import subprocess
import re
import os
import time
from enum import Enum
from dataclasses import dataclass
from threading import Thread, Event
from pathlib import Path


class Backend(Enum):
    AIRCRACK = "aircrack"
    HASHCAT = "hashcat"
    JOHN = "john"


@dataclass
class CrackResult:
    success: bool
    key: str
    backend: str
    duration: float
    attempts: int


class Cracker:
    def __init__(self):
        self._process = None
        self._stop_event = Event()
        self._result = None

    def crack_wpa(self, cap_file, wordlist, bssid=None, backend=Backend.AIRCRACK):
        if backend == Backend.AIRCRACK:
            return self._crack_aircrack_wpa(cap_file, wordlist, bssid)
        if backend == Backend.HASHCAT:
            return self._crack_hashcat_wpa(cap_file, wordlist)
        if backend == Backend.JOHN:
            return self._crack_john_wpa(cap_file, wordlist)
        return CrackResult(False, "", backend.value, 0, 0)

    def crack_wep(self, cap_file):
        start = time.time()
        cmd = ["aircrack-ng", "-0", cap_file]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            output = result.stdout

            match = re.search(r"KEY FOUND!\s*\[\s*([0-9A-Fa-f: ]+)\s*\]", output)
            if match:
                key = match.group(1).replace(":", "").replace(" ", "")
                return CrackResult(True, key, "aircrack", time.time() - start, 0)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return CrackResult(False, "", "aircrack", time.time() - start, 0)

    def crack_pmkid(self, hash_file, wordlist, backend=Backend.HASHCAT):
        if backend == Backend.HASHCAT:
            return self._crack_hashcat_pmkid(hash_file, wordlist)
        return CrackResult(False, "", backend.value, 0, 0)

    def _crack_aircrack_wpa(self, cap_file, wordlist, bssid=None):
        start = time.time()
        cmd = ["aircrack-ng", "-w", wordlist]
        if bssid:
            cmd.extend(["-b", bssid])
        cmd.append(cap_file)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=86400)
            output = result.stdout

            match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
            if match:
                return CrackResult(True, match.group(1), "aircrack", time.time() - start, 0)

            tested = re.search(r"(\d+)\s*keys tested", output)
            attempts = int(tested.group(1)) if tested else 0
            return CrackResult(False, "", "aircrack", time.time() - start, attempts)

        except subprocess.TimeoutExpired:
            return CrackResult(False, "", "aircrack", time.time() - start, 0)
        except FileNotFoundError:
            return CrackResult(False, "", "aircrack", 0, 0)

    def _crack_hashcat_wpa(self, cap_file, wordlist):
        start = time.time()

        hc_file = cap_file
        if cap_file.endswith(".cap") or cap_file.endswith(".pcap"):
            from autowifi.handshake import convert_to_hc22000
            converted = convert_to_hc22000(cap_file)
            if converted:
                hc_file = converted
            else:
                return CrackResult(False, "", "hashcat", 0, 0)

        cmd = [
            "hashcat", "-m", "22000",
            hc_file, wordlist,
            "--force", "-w", "3",
            "--status", "--status-timer", "5",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=86400)
            output = result.stdout

            for line in output.split("\n"):
                if ":" in line and not line.startswith("#") and not line.startswith("Session"):
                    parts = line.split(":")
                    if len(parts) >= 4:
                        key = parts[-1].strip()
                        if key and len(key) >= 8:
                            return CrackResult(True, key, "hashcat", time.time() - start, 0)

            show_cmd = ["hashcat", "-m", "22000", hc_file, "--show"]
            show_result = subprocess.run(show_cmd, capture_output=True, text=True, timeout=30)
            for line in show_result.stdout.strip().split("\n"):
                if ":" in line:
                    key = line.split(":")[-1].strip()
                    if key and len(key) >= 8:
                        return CrackResult(True, key, "hashcat", time.time() - start, 0)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return CrackResult(False, "", "hashcat", time.time() - start, 0)

    def _crack_john_wpa(self, cap_file, wordlist):
        start = time.time()

        hccapx_file = cap_file
        if cap_file.endswith(".cap") or cap_file.endswith(".pcap"):
            from autowifi.handshake import convert_to_hccapx
            converted = convert_to_hccapx(cap_file)
            if converted:
                hccapx_file = converted
            else:
                return CrackResult(False, "", "john", 0, 0)

        cmd = [
            "john", "--wordlist=" + wordlist,
            "--format=wpapsk", hccapx_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=86400)

            show_cmd = ["john", "--show", "--format=wpapsk", hccapx_file]
            show_result = subprocess.run(show_cmd, capture_output=True, text=True, timeout=30)
            for line in show_result.stdout.strip().split("\n"):
                if ":" in line and "0 password" not in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        key = parts[1].strip()
                        if key:
                            return CrackResult(True, key, "john", time.time() - start, 0)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return CrackResult(False, "", "john", time.time() - start, 0)

    def _crack_hashcat_pmkid(self, hash_file, wordlist):
        start = time.time()
        cmd = [
            "hashcat", "-m", "22000",
            hash_file, wordlist,
            "--force", "-w", "3",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=86400)

            show_cmd = ["hashcat", "-m", "22000", hash_file, "--show"]
            show_result = subprocess.run(show_cmd, capture_output=True, text=True, timeout=30)
            for line in show_result.stdout.strip().split("\n"):
                if ":" in line:
                    key = line.split(":")[-1].strip()
                    if key and len(key) >= 8:
                        return CrackResult(True, key, "hashcat", time.time() - start, 0)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return CrackResult(False, "", "hashcat", time.time() - start, 0)

    def stop(self):
        self._stop_event.set()
        if self._process and self._process.poll() is None:
            self._process.kill()


def find_wordlists():
    common_paths = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/john/password.lst",
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
        "/opt/wordlists/rockyou.txt",
    ]
    found = []
    for p in common_paths:
        if os.path.exists(p):
            size = os.path.getsize(p)
            found.append((p, size))
    return found
