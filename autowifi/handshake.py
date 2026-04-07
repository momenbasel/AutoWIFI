import subprocess
import os
import re
import time
import signal
import tempfile
from pathlib import Path
from threading import Thread, Event


class HandshakeCapture:
    def __init__(self, interface, bssid, channel, output_dir=None):
        self.interface = interface
        self.bssid = bssid
        self.channel = channel
        self.output_dir = output_dir or tempfile.mkdtemp(prefix="awf_hs_")
        self._prefix = os.path.join(self.output_dir, "handshake")
        self._process = None
        self._captured = Event()
        self._monitor_thread = None

    @property
    def cap_file(self):
        return self._prefix + "-01.cap"

    def start(self):
        cmd = [
            "airodump-ng",
            "--bssid", self.bssid,
            "--channel", str(self.channel),
            "--write", self._prefix,
            "--output-format", "pcap",
            self.interface,
        ]

        self._process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )

        self._monitor_thread = Thread(target=self._monitor_output, daemon=True)
        self._monitor_thread.start()

    def _monitor_output(self):
        if not self._process:
            return
        try:
            for line in iter(self._process.stdout.readline, ""):
                if not line:
                    break
                if "WPA handshake:" in line and self.bssid.upper() in line.upper():
                    self._captured.set()
        except (ValueError, OSError):
            pass

    def wait(self, timeout=180):
        return self._captured.wait(timeout=timeout)

    @property
    def is_captured(self):
        if self._captured.is_set():
            return True
        if os.path.exists(self.cap_file):
            return verify_handshake(self.cap_file, self.bssid)
        return False

    def stop(self):
        if self._process and self._process.poll() is None:
            self._process.send_signal(signal.SIGTERM)
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None


def verify_handshake(cap_file, bssid=None):
    if not os.path.exists(cap_file):
        return False

    cmd = ["aircrack-ng", cap_file]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr

        if "1 handshake" in output.lower() or "valid handshake" in output.lower():
            if bssid:
                return bssid.upper() in output.upper()
            return True

        if "No valid" in output or "0 handshake" in output:
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    try:
        result = subprocess.run(
            ["tshark", "-r", cap_file, "-Y",
             "eapol && wlan.bssid==" + bssid if bssid else "eapol",
             "-T", "fields", "-e", "eapol.keydes.key_info"],
            capture_output=True, text=True, timeout=15,
        )
        eapol_msgs = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
        return len(eapol_msgs) >= 2
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return False


def clean_handshake(cap_file, output_file=None):
    if output_file is None:
        output_file = cap_file.replace(".cap", "-clean.cap")
    try:
        subprocess.run(
            ["wpaclean", output_file, cap_file],
            capture_output=True, text=True, timeout=30,
        )
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return output_file
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def convert_to_hc22000(cap_file, output_file=None):
    if output_file is None:
        output_file = cap_file.replace(".cap", ".hc22000")
    try:
        subprocess.run(
            ["hcxpcapngtool", "-o", output_file, cap_file],
            capture_output=True, text=True, timeout=30,
        )
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return output_file
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def convert_to_hccapx(cap_file, output_file=None):
    if output_file is None:
        output_file = cap_file.replace(".cap", ".hccapx")
    try:
        subprocess.run(
            ["cap2hccapx", cap_file, output_file],
            capture_output=True, text=True, timeout=30,
        )
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return output_file
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None
