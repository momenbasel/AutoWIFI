import sys
import os
import time
import signal
import click

from autowifi import __version__
from autowifi.config import Config
from autowifi.ui import Display
from autowifi import deps
from autowifi import interface as iface
from autowifi.scanner import NetworkScanner
from autowifi.attacks import (
    WEPAttack, WPAAttack, WPSAttack, PMKIDAttack, Deauth,
    get_recommended_attacks, AttackType,
)
from autowifi.handshake import verify_handshake
from autowifi.cracker import Cracker, Backend, find_wordlists
from autowifi.session import Session
from autowifi.report import ReportGenerator


class AppState:
    def __init__(self):
        self.interface_name = None
        self.monitor_interface = None
        self.interface_mode = None
        self.target = None
        self.networks = []
        self.clients = []
        self.handshake_file = None
        self.pmkid_file = None
        self.session = None
        self.config = Config()
        self.display = Display()
        self.session_mgr = None


def _cleanup(state):
    if state.monitor_interface:
        state.display.info(f"restoring {state.monitor_interface}...")
        iface.disable_monitor(state.monitor_interface)


def _handle_exit(state):
    _cleanup(state)
    state.display.info("exiting")
    sys.exit(0)


def do_select_interface(state):
    interfaces = iface.list_interfaces()
    if not interfaces:
        state.display.error("no wireless interfaces found")
        state.display.info("make sure your adapter is connected and drivers are loaded")
        return

    state.display.interface_table(interfaces)
    state.display.console.print()

    idx = state.display.prompt_int("select interface", default=1, min_val=1, max_val=len(interfaces))
    selected = interfaces[idx - 1]

    state.interface_name = selected.name
    state.interface_mode = selected.mode

    if selected.mode != "Monitor":
        if state.display.confirm("enable monitor mode?", default=True):
            if state.config.get("mac_randomize"):
                state.display.info("randomizing MAC address...")
                iface.set_mac(selected.name)

            with state.display.spinner_context() as progress:
                task = progress.add_task("enabling monitor mode...", total=None)
                mon = iface.enable_monitor(selected.name)

            if mon:
                state.monitor_interface = mon
                state.interface_mode = "Monitor"
                state.display.success(f"monitor mode on {mon}")
            else:
                state.display.error("failed to enable monitor mode")
    else:
        state.monitor_interface = selected.name
        state.display.success(f"using {selected.name} (already in monitor mode)")


def do_scan(state):
    if not state.monitor_interface:
        state.display.error("no monitor interface - select an interface first")
        return

    duration = state.display.prompt_int(
        "scan duration (seconds)",
        default=state.config.get("scan_duration", 30),
        min_val=5, max_val=300,
    )

    scanner = NetworkScanner(state.monitor_interface)

    state.display.console.print()
    with state.display.spinner_context() as progress:
        task = progress.add_task(f"scanning ({duration}s)...", total=None)
        state.networks = scanner.scan(duration=duration)
        state.clients = scanner.clients

    if not state.networks:
        state.display.warning("no networks discovered")
        return

    state.display.console.print()
    state.display.network_table(state.networks)

    if state.clients:
        state.display.console.print()
        state.display.client_table(state.clients)


def do_select_target(state):
    if not state.networks:
        state.display.error("no networks scanned - run a scan first")
        return

    state.display.network_table(state.networks)
    state.display.console.print()

    idx = state.display.prompt_int("select target", default=1, min_val=1, max_val=len(state.networks))
    state.target = state.networks[idx - 1]

    state.display.success(f"target: {state.target.essid or state.target.bssid} [{state.target.encryption}] ch:{state.target.channel}")

    if state.session_mgr:
        state.session_mgr.create(
            state.target.bssid,
            state.target.essid,
            state.target.encryption,
        )


def do_attack(state):
    if not state.target:
        state.display.error("no target selected")
        return
    if not state.monitor_interface:
        state.display.error("no monitor interface")
        return

    attacks = get_recommended_attacks(state.target)
    if not attacks:
        state.display.error(f"no attacks available for {state.target.encryption}")
        return

    state.display.attack_menu(attacks)
    idx = state.display.prompt_int("select attack", default=0, min_val=0, max_val=len(attacks))
    if idx == 0:
        return

    attack_type, attack_name, _ = attacks[idx - 1]
    state.display.console.print()
    state.display.info(f"launching {attack_name} against {state.target.essid or state.target.bssid}")
    state.display.separator()

    result = None

    try:
        if attack_type == AttackType.WEP_ARP_REPLAY:
            result = _run_wep_arp(state)
        elif attack_type == AttackType.WEP_FRAGMENT:
            result = _run_wep_frag(state)
        elif attack_type == AttackType.WEP_CHOPCHOP:
            result = _run_wep_chop(state)
        elif attack_type == AttackType.WPA_HANDSHAKE:
            result = _run_wpa_handshake(state)
        elif attack_type == AttackType.WPS_PIXIE:
            result = _run_wps_pixie(state)
        elif attack_type == AttackType.WPS_BRUTE:
            result = _run_wps_brute(state)
        elif attack_type == AttackType.PMKID:
            result = _run_pmkid(state)
        elif attack_type == AttackType.DEAUTH:
            result = _run_deauth(state)
    except KeyboardInterrupt:
        state.display.warning("attack interrupted")
        return

    if result:
        state.display.console.print()
        if result.success:
            if result.key:
                state.display.key_found(result.key, state.target.essid)
            elif result.handshake_file:
                state.display.success(f"handshake captured: {result.handshake_file}")
                state.handshake_file = result.handshake_file
            elif result.pmkid_file:
                state.display.success(f"PMKID captured: {result.pmkid_file}")
                state.pmkid_file = result.pmkid_file
            elif result.pin:
                state.display.success(f"WPS PIN: {result.pin}")
        else:
            state.display.error(f"attack unsuccessful ({result.duration:.0f}s)")

        if state.session_mgr and state.session_mgr.current:
            state.session_mgr.add_result(result)
            if result.success and result.key:
                state.session_mgr.complete(result.key)


def _run_wep_arp(state):
    atk = WEPAttack(
        state.monitor_interface, state.target.bssid,
        state.target.channel, state.target.essid,
    )
    with state.display.spinner_context() as progress:
        task = progress.add_task("WEP ARP replay attack...", total=None)
        return atk.arp_replay(timeout=int(state.config.get("handshake_timeout", 600)))


def _run_wep_frag(state):
    atk = WEPAttack(
        state.monitor_interface, state.target.bssid,
        state.target.channel, state.target.essid,
    )
    with state.display.spinner_context() as progress:
        task = progress.add_task("WEP fragmentation attack...", total=None)
        return atk.fragmentation(timeout=int(state.config.get("handshake_timeout", 600)))


def _run_wep_chop(state):
    atk = WEPAttack(
        state.monitor_interface, state.target.bssid,
        state.target.channel, state.target.essid,
    )
    with state.display.spinner_context() as progress:
        task = progress.add_task("WEP chopchop attack...", total=None)
        return atk.chopchop(timeout=int(state.config.get("handshake_timeout", 600)))


def _run_wpa_handshake(state):
    clients = [c for c in state.target.clients] if state.target.clients else []
    atk = WPAAttack(
        state.monitor_interface, state.target.bssid,
        state.target.channel, state.target.essid, clients=clients,
    )
    timeout = int(state.config.get("handshake_timeout", 180))
    deauth_count = int(state.config.get("deauth_count", 15))

    with state.display.spinner_context() as progress:
        task = progress.add_task("capturing WPA handshake...", total=None)
        return atk.capture_handshake(deauth_count=deauth_count, timeout=timeout)


def _run_wps_pixie(state):
    atk = WPSAttack(
        state.monitor_interface, state.target.bssid,
        state.target.channel, state.target.essid,
    )
    with state.display.spinner_context() as progress:
        task = progress.add_task("WPS pixie dust attack...", total=None)
        return atk.pixie_dust(timeout=int(state.config.get("wps_timeout", 300)))


def _run_wps_brute(state):
    atk = WPSAttack(
        state.monitor_interface, state.target.bssid,
        state.target.channel, state.target.essid,
    )
    with state.display.spinner_context() as progress:
        task = progress.add_task("WPS PIN brute force...", total=None)
        return atk.brute_force(timeout=int(state.config.get("wps_timeout", 3600)))


def _run_pmkid(state):
    atk = PMKIDAttack(
        state.monitor_interface, state.target.bssid,
        state.target.channel, state.target.essid,
    )
    with state.display.spinner_context() as progress:
        task = progress.add_task("capturing PMKID...", total=None)
        return atk.capture(timeout=60)


def _run_deauth(state):
    count = state.display.prompt_int("deauth packet count (0=continuous)", default=15, min_val=0)
    deauth = Deauth(state.monitor_interface, state.target.bssid, count=count)

    if count == 0:
        state.display.info("continuous deauth - press Ctrl+C to stop")
        deauth.run_continuous()
        try:
            deauth.wait()
        except KeyboardInterrupt:
            deauth.stop()
    else:
        with state.display.spinner_context() as progress:
            task = progress.add_task(f"sending {count} deauth frames...", total=None)
            deauth.run()
            deauth.wait(timeout=30)

    state.display.success("deauthentication complete")
    from autowifi.attacks import AttackResult
    return AttackResult(
        success=True, attack_type="deauth",
        target_bssid=state.target.bssid, target_essid=state.target.essid,
    )


def do_crack(state):
    cap_file = state.handshake_file
    if not cap_file:
        path = state.display.prompt("path to capture file")
        if not path or not os.path.exists(path):
            state.display.error("file not found")
            return
        cap_file = path

    if cap_file.endswith(".cap") or cap_file.endswith(".pcap"):
        bssid = state.target.bssid if state.target else None
        if not verify_handshake(cap_file, bssid):
            state.display.warning("no valid handshake detected in file")
            if not state.display.confirm("continue anyway?"):
                return

    wordlists = find_wordlists()
    if wordlists:
        state.display.wordlist_table(wordlists)
        state.display.console.print(f"  [bright_black][{len(wordlists) + 1}] custom path[/]")
        idx = state.display.prompt_int("select wordlist", default=1, min_val=1, max_val=len(wordlists) + 1)
        if idx <= len(wordlists):
            wordlist = wordlists[idx - 1][0]
        else:
            wordlist = state.display.prompt("wordlist path")
    else:
        wordlist = state.display.prompt("wordlist path", default=state.config.get("default_wordlist", ""))

    if not wordlist or not os.path.exists(wordlist):
        state.display.error("wordlist not found")
        return

    state.display.console.print()
    backends = ["aircrack-ng"]
    from autowifi.deps import check_tool
    if check_tool("hashcat"):
        backends.append("hashcat")
    if check_tool("john"):
        backends.append("john")

    for i, b in enumerate(backends, 1):
        state.display.console.print(f"  [green][{i}][/] {b}")
    idx = state.display.prompt_int("select backend", default=1, min_val=1, max_val=len(backends))
    backend_name = backends[idx - 1]

    backend_map = {
        "aircrack-ng": Backend.AIRCRACK,
        "hashcat": Backend.HASHCAT,
        "john": Backend.JOHN,
    }

    cracker = Cracker()
    state.display.console.print()

    with state.display.spinner_context() as progress:
        task = progress.add_task(f"cracking with {backend_name}...", total=None)
        bssid = state.target.bssid if state.target else None
        result = cracker.crack_wpa(cap_file, wordlist, bssid=bssid, backend=backend_map[backend_name])

    state.display.console.print()
    if result.success:
        state.display.key_found(result.key, state.target.essid if state.target else "")
        if state.session_mgr and state.session_mgr.current:
            state.session_mgr.complete(result.key)
    else:
        state.display.error(f"key not found ({result.attempts} keys tested, {result.duration:.0f}s)")


def do_wps(state):
    if not state.target:
        state.display.error("no target selected")
        return
    if not state.monitor_interface:
        state.display.error("no monitor interface")
        return

    state.display.console.print(f"\n  [green][1][/] Pixie Dust (offline)")
    state.display.console.print(f"  [green][2][/] PIN Brute Force (online)")
    state.display.console.print(f"  [red][0][/] Back")
    state.display.console.print()

    choice = state.display.prompt_int("select attack", default=0, min_val=0, max_val=2)
    if choice == 0:
        return

    try:
        if choice == 1:
            result = _run_wps_pixie(state)
        else:
            result = _run_wps_brute(state)
    except KeyboardInterrupt:
        state.display.warning("interrupted")
        return

    if result and result.success:
        if result.pin:
            state.display.success(f"WPS PIN: {result.pin}")
        if result.key:
            state.display.key_found(result.key, state.target.essid)
    elif result:
        state.display.error("WPS attack unsuccessful")


def do_pmkid(state):
    if not state.target:
        state.display.error("no target selected")
        return
    if not state.monitor_interface:
        state.display.error("no monitor interface")
        return

    try:
        result = _run_pmkid(state)
    except KeyboardInterrupt:
        state.display.warning("interrupted")
        return

    if result and result.success:
        state.display.success(f"PMKID hash saved: {result.pmkid_file}")
        state.pmkid_file = result.pmkid_file
        if state.display.confirm("crack PMKID now?", default=True):
            _crack_pmkid_flow(state, result.pmkid_file)
    elif result:
        state.display.error("PMKID capture failed - target may not support PMKID")


def _crack_pmkid_flow(state, hash_file):
    wordlists = find_wordlists()
    if wordlists:
        state.display.wordlist_table(wordlists)
        idx = state.display.prompt_int("select wordlist", default=1, min_val=1, max_val=len(wordlists))
        wordlist = wordlists[idx - 1][0]
    else:
        wordlist = state.display.prompt("wordlist path")
        if not wordlist or not os.path.exists(wordlist):
            state.display.error("wordlist not found")
            return

    cracker = Cracker()
    with state.display.spinner_context() as progress:
        task = progress.add_task("cracking PMKID...", total=None)
        result = cracker.crack_pmkid(hash_file, wordlist)

    if result.success:
        state.display.key_found(result.key, state.target.essid if state.target else "")
    else:
        state.display.error("PMKID crack failed - try a larger wordlist")


def do_sessions(state):
    if not state.session_mgr:
        state.session_mgr = Session(state.config.get("session_dir"))

    sessions = state.session_mgr.list_sessions()
    if not sessions:
        state.display.info("no saved sessions")
        return

    state.display.session_table(sessions)
    state.display.console.print()
    state.display.console.print(f"  [green][d][/] Delete session")
    state.display.console.print(f"  [red][0][/] Back")

    choice = state.display.prompt("select session or action", default="0")
    if choice == "0":
        return
    if choice.lower() == "d":
        idx = state.display.prompt_int("session # to delete", default=1, min_val=1, max_val=len(sessions))
        sid = sessions[idx - 1]["id"]
        if state.display.confirm(f"delete session {sid}?"):
            state.session_mgr.delete(sid)
            state.display.success("session deleted")
        return


def do_report(state):
    if not state.session_mgr or not state.session_mgr.current:
        if not state.target:
            state.display.error("no active session or target")
            return
        session_data = {
            "target_bssid": state.target.bssid,
            "target_essid": state.target.essid,
            "attack_type": state.target.encryption,
            "status": "manual",
            "results": [],
        }
    else:
        session_data = state.session_mgr.current

    reporter = ReportGenerator(state.config.get("report_dir"))

    state.display.console.print(f"\n  [green][1][/] All formats")
    state.display.console.print(f"  [green][2][/] HTML only")
    state.display.console.print(f"  [green][3][/] JSON only")
    state.display.console.print(f"  [green][4][/] Text only")
    state.display.console.print()

    choice = state.display.prompt_int("format", default=1, min_val=1, max_val=4)
    fmt_map = {1: "all", 2: "html", 3: "json", 4: "txt"}

    files = reporter.generate(session_data, fmt=fmt_map[choice])
    for f in files:
        state.display.success(f"report: {f}")


def do_settings(state):
    state.display.settings_table(state.config.all)
    state.display.console.print()
    state.display.console.print(f"  [green][s][/] Save current config")
    state.display.console.print(f"  [green][e][/] Edit setting")
    state.display.console.print(f"  [red][0][/] Back")

    choice = state.display.prompt("action", default="0")
    if choice == "0":
        return
    if choice.lower() == "s":
        state.config.save()
        state.display.success("configuration saved")
    elif choice.lower() == "e":
        key = state.display.prompt("setting name")
        if key not in state.config.all:
            state.display.error(f"unknown setting: {key}")
            return
        current = state.config.get(key)
        state.display.info(f"current value: {current}")
        new_val = state.display.prompt("new value")
        if isinstance(current, bool):
            state.config.set(key, new_val.lower() in ("true", "1", "yes"))
        elif isinstance(current, int):
            try:
                state.config.set(key, int(new_val))
            except ValueError:
                state.display.error("invalid integer")
                return
        else:
            state.config.set(key, new_val)
        state.display.success(f"{key} = {state.config.get(key)}")


def do_dependencies(state):
    from autowifi.deps import REQUIRED, OPTIONAL, check_tool
    all_deps = {}
    for tool, pkg in REQUIRED.items():
        all_deps[tool] = (check_tool(tool), f"[required] {pkg}")
    for tool, desc in OPTIONAL.items():
        all_deps[tool] = (check_tool(tool), desc)
    state.display.dependency_table(all_deps)


@click.group(invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Show version")
@click.pass_context
def main(ctx, version):
    if version:
        click.echo(f"autowifi v{__version__}")
        return
    if ctx.invoked_subcommand is None:
        interactive_mode()


@main.command()
@click.option("--interface", "-i", default=None, help="Monitor interface")
@click.option("--duration", "-d", default=30, help="Scan duration in seconds")
def scan(interface, duration):
    if not deps.check_root():
        click.echo("[-] root privileges required")
        sys.exit(1)

    config = Config()
    config.load()
    display = Display()

    mon_iface = interface or config.get("interface")
    scanner = NetworkScanner(mon_iface)
    networks = scanner.scan(duration=duration)

    if networks:
        display.network_table(networks)
    else:
        display.warning("no networks found")


@main.command()
@click.option("--interface", "-i", required=True, help="Monitor interface")
@click.option("--bssid", "-b", required=True, help="Target BSSID")
@click.option("--channel", "-c", required=True, type=int, help="Target channel")
@click.option("--essid", "-e", default="", help="Target ESSID")
@click.option("--timeout", "-t", default=180, help="Capture timeout")
def capture(interface, bssid, channel, essid, timeout):
    if not deps.check_root():
        click.echo("[-] root privileges required")
        sys.exit(1)

    display = Display()
    atk = WPAAttack(interface, bssid, channel, essid)

    with display.spinner_context() as progress:
        task = progress.add_task("capturing handshake...", total=None)
        result = atk.capture_handshake(timeout=timeout)

    if result.success:
        display.success(f"handshake saved: {result.handshake_file}")
    else:
        display.error("capture failed")


@main.command()
@click.argument("capfile")
@click.option("--wordlist", "-w", required=True, help="Wordlist path")
@click.option("--bssid", "-b", default=None, help="Target BSSID")
@click.option("--backend", type=click.Choice(["aircrack", "hashcat", "john"]), default="aircrack")
def crack(capfile, wordlist, bssid, backend):
    display = Display()
    backend_map = {
        "aircrack": Backend.AIRCRACK,
        "hashcat": Backend.HASHCAT,
        "john": Backend.JOHN,
    }

    cracker = Cracker()
    with display.spinner_context() as progress:
        task = progress.add_task(f"cracking with {backend}...", total=None)
        result = cracker.crack_wpa(capfile, wordlist, bssid=bssid, backend=backend_map[backend])

    if result.success:
        display.key_found(result.key)
    else:
        display.error(f"key not found ({result.attempts} tested, {result.duration:.0f}s)")


def interactive_mode():
    if not deps.check_root():
        display = Display()
        display.error("root privileges required - run with sudo")
        sys.exit(1)

    if not deps.check_platform():
        display = Display()
        display.warning("designed for Linux - some features may not work on this platform")

    missing = deps.get_missing_required()
    if missing:
        display = Display()
        display.error("missing required tools:")
        for tool, pkg in missing:
            display.error(f"  {tool} (install: {pkg})")
        sys.exit(1)

    state = AppState()
    state.config.load()
    state.session_mgr = Session(state.config.get("session_dir"))

    signal.signal(signal.SIGINT, lambda s, f: _handle_exit(state))

    while True:
        try:
            state.display.clear()
            state.display.banner(__version__)
            state.display.status_bar(
                interface=state.monitor_interface or state.interface_name,
                mode=state.interface_mode,
                target=f"{state.target.essid or state.target.bssid}" if state.target else None,
                session=state.session_mgr._current_id[:12] if state.session_mgr._current_id else None,
            )

            choice = state.display.main_menu()

            if choice == "0":
                _handle_exit(state)
            elif choice == "1":
                do_select_interface(state)
            elif choice == "2":
                do_scan(state)
            elif choice == "3":
                do_select_target(state)
            elif choice == "4":
                do_attack(state)
            elif choice == "5":
                do_crack(state)
            elif choice == "6":
                do_wps(state)
            elif choice == "7":
                do_pmkid(state)
            elif choice == "8":
                do_sessions(state)
            elif choice == "9":
                do_report(state)
            elif choice.lower() == "s":
                do_settings(state)
            elif choice.lower() == "d":
                do_dependencies(state)

            state.display.console.print()
            state.display.wait_key()

        except KeyboardInterrupt:
            state.display.console.print()
            if state.display.confirm("exit?", default=True):
                _handle_exit(state)
        except Exception as exc:
            state.display.error(f"unexpected error: {exc}")
            state.display.wait_key()


if __name__ == "__main__":
    main()
