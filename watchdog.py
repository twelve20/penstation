#!/usr/bin/env python3
"""Network watchdog — detect new/unknown devices joining the LAN."""

import json
import os
import time
from datetime import datetime
from scanner import scan_arp, get_interfaces, merge_devices


KNOWN_DEVICES_FILE = "known_devices.json"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def load_known_devices(path=KNOWN_DEVICES_FILE):
    """Load known devices from JSON file. Returns dict keyed by MAC."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return {d["mac"]: d for d in data}
    except (json.JSONDecodeError, KeyError):
        return {}


def save_known_devices(known, path=KNOWN_DEVICES_FILE):
    """Save known devices dict to JSON file."""
    data = list(known.values())
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def scan_current_devices():
    """Scan all interfaces and return merged device list."""
    interfaces = get_interfaces()
    all_devices = []
    for iface in interfaces:
        devices = scan_arp(interface=iface["name"])
        all_devices.extend(devices)
    return merge_devices(all_devices)


def find_new_devices(current, known):
    """Find devices in current scan that are not in known dict."""
    new = []
    for d in current:
        if d["mac"] not in known:
            new.append(d)
    return new


def find_disappeared(current, known):
    """Find known devices not in current scan."""
    current_macs = {d["mac"] for d in current}
    disappeared = []
    for mac, d in known.items():
        if mac not in current_macs:
            disappeared.append(d)
    return disappeared


def alert_new_device(device):
    """Print alert for a new device."""
    print(f"\n  {RED}{BOLD}[!!!] NEW DEVICE DETECTED{RESET}")
    print(f"  {RED}  IP:     {device['ip']}{RESET}")
    print(f"  {RED}  MAC:    {device['mac']}{RESET}")
    print(f"  {RED}  Vendor: {device.get('vendor', 'Unknown')}{RESET}")
    print("\a", end="")  # terminal bell


def approve_device(device, known, label=""):
    """Add device to known list."""
    entry = {
        "mac": device["mac"],
        "ip": device["ip"],
        "vendor": device.get("vendor", ""),
        "label": label,
        "first_seen": datetime.now().isoformat(),
        "approved": True,
    }
    known[device["mac"]] = entry
    return known


def interactive_review(new_devices, known):
    """Review new devices interactively."""
    for d in new_devices:
        alert_new_device(d)
        print(f"\n  [?] What to do with {d['ip']} ({d['mac']})?")
        print(f"      a = approve (add to known)")
        print(f"      s = skip (alert again next time)")
        print(f"      l = approve with label")
        choice = input("      > ").strip().lower()

        if choice == "a":
            known = approve_device(d, known)
            print(f"  {GREEN}[+] Approved{RESET}")
        elif choice == "l":
            label = input("      Label: ").strip()
            known = approve_device(d, known, label)
            print(f"  {GREEN}[+] Approved as '{label}'{RESET}")
        else:
            print(f"  {YELLOW}[*] Skipped — will alert again{RESET}")

    return known


def print_known_devices(known):
    """Display all known devices."""
    if not known:
        print("\n[*] No known devices saved yet.")
        return

    devices = list(known.values())
    devices.sort(key=lambda d: d.get("ip", ""))

    print(f"\n{'='*74}")
    print(f" Known devices ({len(devices)})")
    print(f"{'='*74}")
    print(f" {'#':<4}{'IP Address':<18}{'MAC Address':<20}{'Label/Vendor'}")
    print(f" {'-'*2:<4}{'-'*16:<18}{'-'*17:<20}{'-'*25}")

    for i, d in enumerate(devices, 1):
        name = d.get("label") or d.get("vendor") or "Unknown"
        print(f" {i:<4}{d.get('ip', '?'):<18}{d['mac']:<20}{name}")

    print(f"{'='*74}\n")


def manage_known_devices():
    """Interactive menu to manage known devices."""
    known = load_known_devices()

    while True:
        print_known_devices(known)
        print("[?] Options:")
        print("    a = add current network devices")
        print("    d = delete by number")
        print("    c = clear all")
        print("    q = back")
        choice = input("    > ").strip().lower()

        if choice == "q":
            break
        elif choice == "a":
            print("[*] Scanning network...")
            current = scan_current_devices()
            for d in current:
                if d["mac"] not in known:
                    known = approve_device(d, known)
                    print(f"  [+] Added {d['ip']} ({d['mac']})")
            save_known_devices(known)
            print(f"[+] Saved {len(known)} device(s)")
        elif choice == "d":
            num = input("    Device #: ").strip()
            try:
                idx = int(num) - 1
                devices = list(known.values())
                if 0 <= idx < len(devices):
                    mac = devices[idx]["mac"]
                    del known[mac]
                    save_known_devices(known)
                    print(f"  [+] Removed")
            except (ValueError, IndexError):
                print("  [!] Invalid number")
        elif choice == "c":
            confirm = input("    Are you sure? (y/n): ").strip().lower()
            if confirm == "y":
                known = {}
                save_known_devices(known)
                print("  [+] Cleared")


def run_watchdog(interval=30):
    """Main watchdog loop — monitors for new devices."""
    print(f"\n[*] PENSTATION — Network Watchdog")
    print(f"[*] Scanning every {interval} seconds (Ctrl+C to stop)")

    known = load_known_devices()

    # initial scan if no known devices
    if not known:
        print("[*] No known devices file found. Running initial scan...")
        current = scan_current_devices()
        for d in current:
            known = approve_device(d, known)
        save_known_devices(known)
        print(f"[+] Saved {len(known)} device(s) as known baseline")
        print_known_devices(known)

    scan_count = 0
    try:
        while True:
            time.sleep(interval)
            scan_count += 1
            now = datetime.now().strftime("%H:%M:%S")
            print(f"\n[*] Scan #{scan_count} at {now}...", end=" ")

            current = scan_current_devices()
            new = find_new_devices(current, known)
            disappeared = find_disappeared(current, known)

            if not new and not disappeared:
                print(f"{GREEN}OK{RESET} — {len(current)} device(s), no changes")
                continue

            if disappeared:
                print(f"\n  {YELLOW}[*] {len(disappeared)} device(s) went offline:{RESET}")
                for d in disappeared:
                    name = d.get("label") or d.get("vendor") or "?"
                    print(f"      {d.get('ip', '?')} — {name}")

            if new:
                print(f"\n  {RED}{BOLD}[!] {len(new)} NEW device(s) detected!{RESET}")
                known = interactive_review(new, known)
                save_known_devices(known)

    except KeyboardInterrupt:
        print(f"\n\n[*] Watchdog stopped. {scan_count} scan(s) completed.")
