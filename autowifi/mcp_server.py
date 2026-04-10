"""MCP (Model Context Protocol) server for AutoWIFI.

Exposes wireless pentesting tools to AI coding assistants:
Claude Code, Codex, Gemini, Cursor, etc.

Usage:
  autowifi-mcp              # stdio mode (default for Claude Code / Cursor)

Config for Claude Code (~/.claude/settings.json):
  {
    "mcpServers": {
      "autowifi": {
        "command": "autowifi-mcp"
      }
    }
  }
"""

import json
import sys
from typing import Any

from mcp.server import Server
from mcp.server.stdio import run_stdio
from mcp.types import TextContent, Tool

from autowifi import deps
from autowifi import interface as iface
from autowifi.scanner import NetworkScanner
from autowifi.attacks import (
    WPAAttack, WPSAttack, PMKIDAttack, Deauth,
    get_recommended_attacks,
)
from autowifi.cracker import Cracker, Backend, find_wordlists
from autowifi.handshake import verify_handshake

server = Server("autowifi")

# Shared state across tool calls
_state = {
    "monitor_interface": None,
    "networks": [],
    "target": None,
    "handshake_file": None,
    "pmkid_file": None,
}


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="list_interfaces",
            description="List wireless network interfaces and their status (mode, MAC, driver, chipset)",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="enable_monitor",
            description="Enable monitor mode on a wireless interface. Required before scanning or attacking.",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Interface name (e.g., wlan0)"},
                },
                "required": ["interface"],
            },
        ),
        Tool(
            name="disable_monitor",
            description="Disable monitor mode and restore the interface to managed mode.",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Monitor interface name (e.g., wlan0mon)"},
                },
                "required": ["interface"],
            },
        ),
        Tool(
            name="scan_networks",
            description="Scan for WiFi networks. Returns BSSID, ESSID, channel, encryption, signal strength, WPS status, and connected clients.",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Monitor mode interface"},
                    "duration": {"type": "integer", "description": "Scan duration in seconds", "default": 30},
                },
                "required": ["interface"],
            },
        ),
        Tool(
            name="get_recommended_attacks",
            description="Get recommended attack vectors for a target network based on its encryption type.",
            inputSchema={
                "type": "object",
                "properties": {
                    "network_index": {"type": "integer", "description": "Index from scan_networks results (0-based)"},
                },
                "required": ["network_index"],
            },
        ),
        Tool(
            name="capture_handshake",
            description="Capture a WPA/WPA2 4-way handshake from a target network by sending deauth frames.",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Monitor mode interface"},
                    "bssid": {"type": "string", "description": "Target BSSID"},
                    "channel": {"type": "integer", "description": "Target channel"},
                    "essid": {"type": "string", "description": "Target ESSID", "default": ""},
                    "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 180},
                },
                "required": ["interface", "bssid", "channel"],
            },
        ),
        Tool(
            name="capture_pmkid",
            description="Capture PMKID hash from a target network (clientless attack, no deauth needed).",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Monitor mode interface"},
                    "bssid": {"type": "string", "description": "Target BSSID"},
                    "channel": {"type": "integer", "description": "Target channel"},
                    "essid": {"type": "string", "description": "Target ESSID", "default": ""},
                    "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 60},
                },
                "required": ["interface", "bssid", "channel"],
            },
        ),
        Tool(
            name="wps_pixie_dust",
            description="Run WPS Pixie Dust offline attack against a WPS-enabled target.",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Monitor mode interface"},
                    "bssid": {"type": "string", "description": "Target BSSID"},
                    "channel": {"type": "integer", "description": "Target channel"},
                    "essid": {"type": "string", "description": "Target ESSID", "default": ""},
                    "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 300},
                },
                "required": ["interface", "bssid", "channel"],
            },
        ),
        Tool(
            name="deauth",
            description="Send deauthentication frames to disconnect clients from a target network.",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Monitor mode interface"},
                    "bssid": {"type": "string", "description": "Target BSSID"},
                    "count": {"type": "integer", "description": "Number of deauth frames (0=continuous)", "default": 15},
                },
                "required": ["interface", "bssid"],
            },
        ),
        Tool(
            name="crack_handshake",
            description="Crack a captured WPA handshake or PMKID hash using a wordlist.",
            inputSchema={
                "type": "object",
                "properties": {
                    "capture_file": {"type": "string", "description": "Path to .cap/.pcap or PMKID hash file"},
                    "wordlist": {"type": "string", "description": "Path to wordlist file"},
                    "bssid": {"type": "string", "description": "Target BSSID (optional)"},
                    "backend": {"type": "string", "enum": ["aircrack", "hashcat", "john"], "default": "aircrack"},
                },
                "required": ["capture_file", "wordlist"],
            },
        ),
        Tool(
            name="verify_handshake",
            description="Verify if a capture file contains a valid WPA handshake.",
            inputSchema={
                "type": "object",
                "properties": {
                    "capture_file": {"type": "string", "description": "Path to .cap/.pcap file"},
                    "bssid": {"type": "string", "description": "Expected BSSID (optional)"},
                },
                "required": ["capture_file"],
            },
        ),
        Tool(
            name="find_wordlists",
            description="Discover wordlists installed on the system (rockyou, seclists, etc.).",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="check_dependencies",
            description="Check which required and optional tools are installed (aircrack-ng, hashcat, reaver, etc.).",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


def _serialize_network(net) -> dict:
    return {
        "bssid": net.bssid,
        "essid": net.essid,
        "channel": net.channel,
        "encryption": net.encryption,
        "cipher": net.cipher,
        "auth": net.auth,
        "power": net.power,
        "wps": net.wps,
        "clients": len(net.clients) if net.clients else 0,
    }


def _serialize_result(result) -> dict:
    return {
        "success": result.success,
        "key": result.key if hasattr(result, "key") else None,
        "pin": result.pin if hasattr(result, "pin") else None,
        "handshake_file": result.handshake_file if hasattr(result, "handshake_file") else None,
        "pmkid_file": result.pmkid_file if hasattr(result, "pmkid_file") else None,
        "duration": f"{result.duration:.1f}s" if hasattr(result, "duration") and result.duration else None,
    }


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        result = _dispatch(name, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e)}))]


def _dispatch(name: str, args: dict) -> Any:
    if name == "list_interfaces":
        interfaces = iface.list_interfaces()
        return [{"name": i.name, "mode": i.mode, "mac": i.mac, "driver": i.driver, "chipset": i.chipset} for i in interfaces]

    elif name == "enable_monitor":
        mon = iface.enable_monitor(args["interface"])
        if mon:
            _state["monitor_interface"] = mon
            return {"success": True, "monitor_interface": mon}
        return {"success": False, "error": "Failed to enable monitor mode"}

    elif name == "disable_monitor":
        iface.disable_monitor(args["interface"])
        _state["monitor_interface"] = None
        return {"success": True}

    elif name == "scan_networks":
        scanner = NetworkScanner(args["interface"])
        networks = scanner.scan(duration=args.get("duration", 30))
        _state["networks"] = networks
        return {"count": len(networks), "networks": [_serialize_network(n) for n in networks]}

    elif name == "get_recommended_attacks":
        idx = args["network_index"]
        if idx < 0 or idx >= len(_state["networks"]):
            return {"error": f"Invalid index. {len(_state['networks'])} networks available."}
        net = _state["networks"][idx]
        attacks = get_recommended_attacks(net)
        return {
            "target": _serialize_network(net),
            "attacks": [{"type": str(a[0].value), "name": a[1], "description": a[2]} for a in attacks],
        }

    elif name == "capture_handshake":
        atk = WPAAttack(args["interface"], args["bssid"], args["channel"], args.get("essid", ""))
        result = atk.capture_handshake(timeout=args.get("timeout", 180))
        if result.handshake_file:
            _state["handshake_file"] = result.handshake_file
        return _serialize_result(result)

    elif name == "capture_pmkid":
        atk = PMKIDAttack(args["interface"], args["bssid"], args["channel"], args.get("essid", ""))
        result = atk.capture(timeout=args.get("timeout", 60))
        if result.pmkid_file:
            _state["pmkid_file"] = result.pmkid_file
        return _serialize_result(result)

    elif name == "wps_pixie_dust":
        from autowifi.attacks import WPSAttack
        atk = WPSAttack(args["interface"], args["bssid"], args["channel"], args.get("essid", ""))
        result = atk.pixie_dust(timeout=args.get("timeout", 300))
        return _serialize_result(result)

    elif name == "deauth":
        d = Deauth(args["interface"], args["bssid"], count=args.get("count", 15))
        d.run()
        d.wait(timeout=30)
        return {"success": True, "count": args.get("count", 15)}

    elif name == "crack_handshake":
        backend_map = {"aircrack": Backend.AIRCRACK, "hashcat": Backend.HASHCAT, "john": Backend.JOHN}
        cracker = Cracker()
        backend = backend_map.get(args.get("backend", "aircrack"), Backend.AIRCRACK)
        result = cracker.crack_wpa(args["capture_file"], args["wordlist"], bssid=args.get("bssid"), backend=backend)
        return {"success": result.success, "key": result.key, "attempts": result.attempts, "duration": f"{result.duration:.1f}s"}

    elif name == "verify_handshake":
        valid = verify_handshake(args["capture_file"], args.get("bssid"))
        return {"valid": valid, "file": args["capture_file"]}

    elif name == "find_wordlists":
        wl = find_wordlists()
        return [{"path": w[0], "size": w[1], "name": w[2]} for w in wl]

    elif name == "check_dependencies":
        from autowifi.deps import REQUIRED, OPTIONAL, check_tool
        result = {}
        for tool, pkg in REQUIRED.items():
            result[tool] = {"installed": check_tool(tool), "required": True, "install": pkg}
        for tool, desc in OPTIONAL.items():
            result[tool] = {"installed": check_tool(tool), "required": False, "description": desc}
        return result

    return {"error": f"Unknown tool: {name}"}


def main():
    """Entry point for autowifi-mcp command."""
    import asyncio
    asyncio.run(run_stdio(server))


if __name__ == "__main__":
    main()
