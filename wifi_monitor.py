#!/usr/bin/env python3
"""Wi-Fi monitor — scan nearby wireless networks and clients."""

import subprocess
import re
import os
import glob
import signal
import time


def find_wifi_interface():
    """Find external USB Wi-Fi adapter (not the onboard wlan0)."""
    interfaces = []
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        current_iface = None
        for line in result.stdout.splitlines():
            iface_match = re.search(r"Interface\s+(\S+)", line)
            if iface_match:
                current_iface = iface_match.group(1)
                interfaces.append(current_iface)
    except FileNotFoundError:
        print("[!] iw not found. Install: sudo apt install iw")
        return None

    # prefer external adapter (not wlan0 which is onboard)
    for iface in interfaces:
        if iface != "wlan0" and not iface.endswith("mon"):
            # check if it supports monitor mode
            try:
                result = subprocess.run(
                    ["iw", "phy", f"phy{_get_phy(iface)}", "info"],
                    capture_output=True, text=True, timeout=5
                )
                if "monitor" in result.stdout:
                    return iface
            except Exception:
                return iface

    # fallback: return any non-mon interface
    for iface in interfaces:
        if not iface.endswith("mon"):
            return iface

    return None


def _get_phy(iface):
    """Get phy number for an interface."""
    try:
        phy_path = f"/sys/class/net/{iface}/phy80211/index"
        if os.path.exists(phy_path):
            with open(phy_path) as f:
                return f.read().strip()
    except Exception:
        pass
    return "0"


def get_monitor_interfaces():
    """Find any already-active monitor mode interfaces."""
    interfaces = []
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        current_iface = None
        current_type = None
        for line in result.stdout.splitlines():
            iface_match = re.search(r"Interface\s+(\S+)", line)
            if iface_match:
                if current_iface and current_type == "monitor":
                    interfaces.append(current_iface)
                current_iface = iface_match.group(1)
                current_type = None
            type_match = re.search(r"type\s+(\S+)", line)
            if type_match:
                current_type = type_match.group(1)
        if current_iface and current_type == "monitor":
            interfaces.append(current_iface)
    except Exception:
        pass
    return interfaces


def _verify_monitor_mode(iface):
    """Check if interface is actually in monitor mode via iwconfig."""
    try:
        result = subprocess.run(["iwconfig", iface],
                                capture_output=True, text=True, timeout=5)
        return "Mode:Monitor" in result.stdout
    except Exception:
        return False


def enable_monitor_mode(iface):
    """Enable monitor mode on interface. Returns monitor interface name."""
    print(f"[*] Enabling monitor mode on {iface}...")
    print("[!] This will temporarily disrupt Wi-Fi connections")

    # kill interfering processes
    subprocess.run(["airmon-ng", "check", "kill"],
                   capture_output=True, timeout=10)

    result = subprocess.run(
        ["airmon-ng", "start", iface],
        capture_output=True, text=True, timeout=15
    )

    # find the monitor interface name
    mon_iface = f"{iface}mon"
    # check if it was renamed
    match = re.search(r"monitor mode.*?enabled.*?(\w+mon\w*)", result.stdout, re.IGNORECASE)
    if match:
        mon_iface = match.group(1)

    # verify via iw dev (check for type monitor)
    mon_interfaces = get_monitor_interfaces()
    if mon_interfaces:
        mon_iface = mon_interfaces[0]
        print(f"[+] Monitor mode: {mon_iface}")
        return mon_iface

    # on newer Kali, airmon-ng keeps the same interface name in monitor mode
    # check if the original interface is now in monitor mode
    if _verify_monitor_mode(iface):
        print(f"[+] Monitor mode: {iface} (name unchanged)")
        return iface

    # try alternate naming
    for name in [f"{iface}mon", "wlan1mon", "wlan0mon"]:
        check = subprocess.run(["ip", "link", "show", name],
                               capture_output=True, timeout=5)
        if check.returncode == 0:
            if _verify_monitor_mode(name):
                print(f"[+] Monitor mode: {name}")
                return name

    # last resort: try iw to set monitor mode manually
    print(f"[!] airmon-ng didn't activate monitor mode, trying iw...")
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["iw", iface, "set", "type", "monitor"],
                       capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
        if _verify_monitor_mode(iface):
            print(f"[+] Monitor mode: {iface} (via iw)")
            return iface
    except Exception:
        pass

    print(f"[!] Could not verify monitor interface, trying {mon_iface}")
    return mon_iface


def disable_monitor_mode(mon_iface):
    """Disable monitor mode and restore managed mode."""
    print(f"[*] Disabling monitor mode on {mon_iface}...")
    subprocess.run(["airmon-ng", "stop", mon_iface],
                   capture_output=True, timeout=10)

    # if airmon-ng didn't switch back, use iw
    if _verify_monitor_mode(mon_iface):
        try:
            subprocess.run(["ip", "link", "set", mon_iface, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", mon_iface, "set", "type", "managed"],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", mon_iface, "up"],
                           capture_output=True, timeout=5)
        except Exception:
            pass

    # restart NetworkManager
    subprocess.run(["systemctl", "start", "NetworkManager"],
                   capture_output=True, timeout=10)
    print("[+] Monitor mode disabled, NetworkManager restarted")


def run_airodump(mon_iface, duration=20, output_prefix="/tmp/penstation_wifi"):
    """Run airodump-ng for specified duration. Returns path to CSV file."""
    # clean old files
    for f in glob.glob(f"{output_prefix}*"):
        os.remove(f)

    # make sure interface is UP before scanning
    subprocess.run(["ip", "link", "set", mon_iface, "up"],
                   capture_output=True, timeout=5)

    print(f"[*] Scanning Wi-Fi on {mon_iface} for {duration} seconds...")

    # don't use --band flag — ath9k_htc adapters are 2.4GHz only
    # and --band abg can cause silent failure on single-band cards
    err_path = f"{output_prefix}_stderr.log"
    err_file = open(err_path, "w")

    proc = subprocess.Popen(
        ["airodump-ng", "--write", output_prefix, "--output-format", "csv",
         mon_iface],
        stdout=subprocess.DEVNULL,
        stderr=err_file,
    )

    # check if airodump-ng died immediately
    time.sleep(2)
    if proc.poll() is not None:
        err_file.close()
        print(f"[!] airodump-ng exited immediately (code {proc.returncode})")
        try:
            with open(err_path, "r") as ef:
                print(f"[!] stderr: {ef.read().strip()[:300]}")
        except Exception:
            pass
        return None

    # wait remaining time
    time.sleep(max(0, duration - 2))

    # airodump-ng needs SIGINT to flush and close CSV properly
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    err_file.close()

    # always show stderr for diagnostics
    try:
        with open(err_path, "r") as ef:
            errors = ef.read().strip()
        if errors:
            # filter out ncurses garbage, show meaningful lines
            lines = errors.splitlines()
            useful = [l for l in lines if l.strip()
                      and not l.startswith("\x1b")
                      and "CH" not in l[:10]]
            if useful:
                print(f"[*] airodump-ng output: {useful[0][:150]}")
        os.remove(err_path)
    except Exception:
        pass

    # find the CSV file
    csv_files = glob.glob(f"{output_prefix}*.csv")
    if csv_files:
        csv_path = csv_files[0]
        try:
            with open(csv_path, "r") as cf:
                content = cf.read()
            size = len(content.strip())
            print(f"[*] CSV file: {csv_path} ({size} bytes)")
            if size < 50:
                print(f"[!] CSV nearly empty — airodump-ng captured nothing")
                print(f"[!] Debug: run manually:")
                print(f"    sudo airodump-ng {mon_iface}")
                print(f"    sudo iw dev {mon_iface} info")
        except Exception:
            pass
        return csv_path

    print("[!] No CSV output from airodump-ng")
    print("[!] Debug: run manually:")
    print(f"    sudo airodump-ng {mon_iface}")
    return None


def parse_airodump_csv(csv_path):
    """Parse airodump-ng CSV into APs and clients."""
    aps = []
    clients = []

    if not csv_path or not os.path.exists(csv_path):
        return aps, clients

    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # split into AP section and client section
    sections = re.split(r"\n\s*\n", content)

    # parse APs (first section)
    if len(sections) >= 1:
        lines = sections[0].strip().splitlines()
        for line in lines[1:]:  # skip header
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 14:
                continue
            try:
                bssid = parts[0]
                if not re.match(r"[0-9A-Fa-f:]{17}", bssid):
                    continue
                ap = {
                    "bssid": bssid,
                    "channel": parts[3].strip(),
                    "speed": parts[4].strip(),
                    "encryption": parts[5].strip(),
                    "cipher": parts[6].strip(),
                    "auth": parts[7].strip(),
                    "power": int(parts[8].strip()) if parts[8].strip().lstrip('-').isdigit() else -1,
                    "beacons": parts[9].strip(),
                    "data": parts[10].strip(),
                    "essid": parts[13].strip() if len(parts) > 13 else "",
                }
                if ap["power"] != -1:  # filter out invalid readings
                    aps.append(ap)
            except (ValueError, IndexError):
                continue

    # parse clients (second section)
    if len(sections) >= 2:
        lines = sections[1].strip().splitlines()
        for line in lines[1:]:  # skip header
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 6:
                continue
            try:
                station = parts[0]
                if not re.match(r"[0-9A-Fa-f:]{17}", station):
                    continue
                client = {
                    "mac": station,
                    "bssid": parts[5].strip() if len(parts) > 5 else "",
                    "power": int(parts[3].strip()) if parts[3].strip().lstrip('-').isdigit() else -1,
                    "probed": parts[6].strip() if len(parts) > 6 else "",
                }
                if client["power"] != -1:
                    clients.append(client)
            except (ValueError, IndexError):
                continue

    # sort APs by signal strength (strongest first)
    aps.sort(key=lambda a: a["power"], reverse=True)

    return aps, clients


def print_wifi_results(aps, clients):
    """Display Wi-Fi scan results."""
    # APs table
    print(f"\n{'='*80}")
    print(f" Wi-Fi Networks ({len(aps)} found)")
    print(f"{'='*80}")

    if aps:
        print(f" {'#':<4}{'ESSID':<28}{'BSSID':<20}{'Ch':<5}{'Enc':<10}{'Signal'}")
        print(f" {'-'*2:<4}{'-'*26:<28}{'-'*17:<20}{'-'*3:<5}{'-'*8:<10}{'-'*8}")

        for i, ap in enumerate(aps, 1):
            essid = ap["essid"][:26] or "<hidden>"
            enc = ap["encryption"]
            signal = f"{ap['power']} dBm"
            print(f" {i:<4}{essid:<28}{ap['bssid']:<20}{ap['channel']:<5}{enc:<10}{signal}")
    else:
        print(" No networks found")

    # clients table
    if clients:
        # build BSSID → ESSID mapping
        bssid_map = {ap["bssid"]: ap["essid"] for ap in aps}

        print(f"\n{'-'*80}")
        print(f" Wi-Fi Clients ({len(clients)} found)")
        print(f"{'-'*80}")
        print(f" {'MAC Address':<20}{'Associated Network':<28}{'Signal':<10}{'Probed'}")
        print(f" {'-'*17:<20}{'-'*26:<28}{'-'*8:<10}{'-'*15}")

        for c in clients:
            network = bssid_map.get(c["bssid"], c["bssid"])[:26]
            if c["bssid"] == "(not associated)":
                network = "(roaming)"
            signal = f"{c['power']} dBm"
            probed = c["probed"][:15]
            print(f" {c['mac']:<20}{network:<28}{signal:<10}{probed}")

    print(f"{'='*80}\n")


def scan_wifi(duration=20):
    """Full Wi-Fi scan: enable monitor → scan → parse → disable monitor."""
    # check if airmon-ng is available
    try:
        subprocess.run(["airmon-ng", "--help"], capture_output=True, timeout=5)
    except FileNotFoundError:
        print("[!] aircrack-ng not found. Install: sudo apt install aircrack-ng")
        return None

    # check for existing monitor interfaces
    mon_interfaces = get_monitor_interfaces()
    if mon_interfaces:
        mon_iface = mon_interfaces[0]
        print(f"[*] Using existing monitor interface: {mon_iface}")
    else:
        iface = find_wifi_interface()
        if not iface:
            print("[!] No Wi-Fi adapter found for monitor mode")
            print("    Plug in your TP-Link TL-WN722N or similar adapter")
            return None

        print(f"[*] Found Wi-Fi adapter: {iface}")
        print("[?] Enable monitor mode? This will kill Wi-Fi connections. (y/n)")
        choice = input("    > ").strip().lower()
        if choice != "y":
            print("[*] Cancelled")
            return None

        mon_iface = enable_monitor_mode(iface)

    # verify monitor mode is actually active before scanning
    if _verify_monitor_mode(mon_iface):
        print(f"[+] Verified: {mon_iface} is in Monitor mode")
    else:
        print(f"[!] WARNING: {mon_iface} may not be in monitor mode")

    # show interface details for diagnostics
    try:
        result = subprocess.run(["iw", "dev", mon_iface, "info"],
                                capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            line = line.strip()
            if any(k in line for k in ["type", "channel", "txpower", "addr"]):
                print(f"    {line}")
    except Exception:
        pass

    # run scan
    csv_path = run_airodump(mon_iface, duration)
    aps, clients = parse_airodump_csv(csv_path)

    # disable monitor mode (unless it was already active)
    if not mon_interfaces:
        disable_monitor_mode(mon_iface)

    # display results
    print_wifi_results(aps, clients)

    # cleanup
    for f in glob.glob("/tmp/penstation_wifi*"):
        os.remove(f)

    return {"aps": aps, "clients": clients}


def interactive_wifi_scan():
    """Interactive Wi-Fi monitoring menu."""
    print("\n[?] Wi-Fi scan duration (seconds, default 20):")
    dur = input("    > ").strip()
    try:
        duration = int(dur) if dur else 20
    except ValueError:
        duration = 20

    return scan_wifi(duration)
