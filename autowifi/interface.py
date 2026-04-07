import subprocess
import re
import random
from dataclasses import dataclass


@dataclass
class InterfaceInfo:
    name: str
    mode: str
    mac: str
    driver: str
    chipset: str


def _run(cmd, timeout=30):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 1
    except FileNotFoundError:
        return "", f"{cmd[0]} not found", 127


def list_interfaces():
    interfaces = []
    stdout, _, rc = _run(["airmon-ng"])
    if rc != 0:
        return interfaces

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("PHY") or line.startswith("Interface"):
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            iface = parts[1].strip()
            driver = parts[2].strip() if len(parts) > 2 else ""
            chipset = parts[3].strip() if len(parts) > 3 else ""
            mode = get_mode(iface)
            mac = get_mac(iface)
            interfaces.append(InterfaceInfo(
                name=iface, mode=mode, mac=mac,
                driver=driver, chipset=chipset,
            ))

    return interfaces


def get_mode(interface):
    stdout, _, _ = _run(["iwconfig", interface])
    match = re.search(r"Mode:(\w+)", stdout)
    return match.group(1) if match else "Unknown"


def get_mac(interface):
    stdout, _, _ = _run(["ip", "link", "show", interface])
    match = re.search(r"link/ether\s+([0-9a-f:]+)", stdout, re.I)
    return match.group(1).upper() if match else "00:00:00:00:00:00"


def enable_monitor(interface):
    _run(["airmon-ng", "check", "kill"])

    stdout, stderr, rc = _run(["airmon-ng", "start", interface])
    combined = stdout + stderr

    match = re.search(
        r"\(monitor mode (?:vif )?enabled (?:for \[.*\] )?on\s+(\w+)\)",
        combined,
    )
    if match:
        return match.group(1)

    mon_name = interface + "mon"
    check_out, _, _ = _run(["iwconfig", mon_name])
    if "Monitor" in check_out:
        return mon_name

    check_out, _, _ = _run(["iwconfig", interface])
    if "Monitor" in check_out:
        return interface

    return None


def disable_monitor(interface):
    _, _, rc = _run(["airmon-ng", "stop", interface])
    if rc == 0:
        _run(["systemctl", "start", "NetworkManager"], timeout=10)
        _run(["systemctl", "start", "wpa_supplicant"], timeout=10)
        return True
    return False


def set_mac(interface, mac=None):
    if mac is None:
        mac = _random_mac()
    _run(["ip", "link", "set", interface, "down"])
    stdout, _, rc = _run(["macchanger", "-m", mac, interface])
    if rc != 0:
        _run(["ip", "link", "set", interface, "address", mac])
    _run(["ip", "link", "set", interface, "up"])
    return get_mac(interface).lower() == mac.lower()


def restore_mac(interface):
    _run(["ip", "link", "set", interface, "down"])
    _run(["macchanger", "-p", interface])
    _run(["ip", "link", "set", interface, "up"])


def set_channel(interface, channel):
    _, _, rc = _run(["iwconfig", interface, "channel", str(channel)])
    return rc == 0


def set_txpower(interface, dbm=30):
    _, _, rc = _run(["iwconfig", interface, "txpower", f"{dbm}dBm"])
    return rc == 0


def _random_mac():
    oui_list = [
        "00:11:22", "00:1A:2B", "00:25:9C",
        "00:0C:29", "00:50:56", "08:00:27",
    ]
    oui = random.choice(oui_list)
    nic = ":".join(f"{random.randint(0, 255):02x}" for _ in range(3))
    return f"{oui}:{nic}"
