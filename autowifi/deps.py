import shutil
import os
import platform


REQUIRED = {
    "airmon-ng": "aircrack-ng",
    "airodump-ng": "aircrack-ng",
    "aireplay-ng": "aircrack-ng",
    "aircrack-ng": "aircrack-ng",
    "iwconfig": "wireless-tools",
    "ip": "iproute2",
}

OPTIONAL = {
    "hashcat": "GPU-accelerated cracking",
    "john": "John the Ripper",
    "reaver": "WPS brute force",
    "bully": "WPS brute force (alt)",
    "wash": "WPS network discovery",
    "hcxdumptool": "PMKID capture",
    "hcxpcapngtool": "PMKID conversion",
    "packetforge-ng": "WEP packet forging",
    "macchanger": "MAC spoofing",
    "mdk4": "Advanced deauth/DoS",
    "tshark": "Packet analysis",
    "wpaclean": "Handshake cleaning",
    "hostapd": "Evil twin AP",
    "dnsmasq": "DHCP/DNS for evil twin",
    "pixiewps": "WPS pixie dust offline",
}


def check_root():
    return os.geteuid() == 0


def check_tool(name):
    return shutil.which(name) is not None


def check_all():
    results = {}
    for tool in REQUIRED:
        results[tool] = check_tool(tool)
    for tool in OPTIONAL:
        results[tool] = check_tool(tool)
    return results


def get_missing_required():
    return [(t, p) for t, p in REQUIRED.items() if not check_tool(t)]


def get_available_optional():
    return [(t, d) for t, d in OPTIONAL.items() if check_tool(t)]


def get_missing_optional():
    return [(t, d) for t, d in OPTIONAL.items() if not check_tool(t)]


def check_platform():
    return platform.system() == "Linux"
