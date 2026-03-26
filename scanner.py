#!/usr/bin/env python3
"""Simple LAN device scanner for Raspberry Pi 3B+ with Kali Linux."""

import subprocess
import sys
import json
import re
import socket
import time
from datetime import datetime


def get_interfaces():
    """Get all active network interfaces with their IPs."""
    interfaces = []
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            # e.g.: 2: eth0    inet 192.168.1.49/24 brd ...
            match = re.search(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if match:
                iface = match.group(1)
                ip = match.group(2)
                prefix = int(match.group(3))
                if iface == "lo":
                    continue
                interfaces.append({"name": iface, "ip": ip, "prefix": prefix})
    except Exception:
        pass
    return interfaces


def get_subnet(ip, prefix=24):
    """Derive subnet from IP."""
    parts = ip.split(".")
    if prefix <= 24:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/{prefix}"
    return f"{ip}/{prefix}"


def scan_arp(interface=None):
    """ARP scan using arp-scan (fast, requires root)."""
    devices = []
    try:
        cmd = ["arp-scan", "--localnet", "--retry=3", "--timeout=1000"]
        if interface:
            cmd += ["-I", interface]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            match = re.match(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)", line
            )
            if match:
                devices.append({
                    "ip": match.group(1),
                    "mac": match.group(2).lower(),
                    "vendor": match.group(3).strip(),
                })
    except FileNotFoundError:
        print("[!] arp-scan not found. Install: sudo apt install arp-scan")
    except subprocess.TimeoutExpired:
        print("[!] arp-scan timed out")
    return devices


def scan_nmap_ping(subnet):
    """Ping scan using nmap (fallback if arp-scan unavailable)."""
    devices = []
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-T4", "--min-parallelism=10", subnet],
            capture_output=True, text=True, timeout=60
        )
        current_ip = None
        current_mac = None
        current_vendor = ""

        for line in result.stdout.splitlines():
            ip_match = re.search(r"Nmap scan report for .*?(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                if current_ip:
                    devices.append({
                        "ip": current_ip,
                        "mac": current_mac or "N/A",
                        "vendor": current_vendor,
                    })
                current_ip = ip_match.group(1)
                current_mac = None
                current_vendor = ""

            mac_match = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})\s*(.*)", line)
            if mac_match:
                current_mac = mac_match.group(1).lower()
                current_vendor = mac_match.group(2).strip("() ")

        if current_ip:
            devices.append({
                "ip": current_ip,
                "mac": current_mac or "N/A",
                "vendor": current_vendor,
            })
    except FileNotFoundError:
        print("[!] nmap not found. Install: sudo apt install nmap")
    except subprocess.TimeoutExpired:
        print("[!] nmap timed out")
    return devices


def resolve_hostname(ip):
    """Try to resolve hostname for an IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ""


def merge_devices(all_devices):
    """Merge device lists by MAC, keeping all unique entries."""
    seen = {}
    for d in all_devices:
        key = d["mac"]
        if key not in seen or seen[key]["vendor"] == "":
            seen[key] = d
    return list(seen.values())


def print_devices(devices, local_ip=None):
    """Pretty-print discovered devices."""
    if not devices:
        print("\n[!] No devices found.")
        return

    for d in devices:
        d["hostname"] = resolve_hostname(d["ip"])

    devices.sort(key=lambda d: tuple(int(p) for p in d["ip"].split(".")))

    print(f"\n{'='*74}")
    print(f" Found {len(devices)} device(s) on the local network")
    print(f"{'='*74}")
    print(f" {'IP Address':<18}{'MAC Address':<20}{'Vendor/Hostname'}")
    print(f" {'-'*16:<18}{'-'*17:<20}{'-'*33}")

    for d in devices:
        name = d["hostname"] or d["vendor"] or "Unknown"
        marker = " <-- you" if d["ip"] == local_ip else ""
        print(f" {d['ip']:<18}{d['mac']:<20}{name}{marker}")

    print(f"{'='*74}\n")


def save_results(devices, filename="scan_results.json"):
    """Save scan results to JSON file."""
    data = {
        "scan_time": datetime.now().isoformat(),
        "device_count": len(devices),
        "devices": devices,
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Results saved to {filename}")


def main():
    print("\n[*] PENSTATION — Simple LAN Scanner")
    print(f"[*] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    interfaces = get_interfaces()
    if not interfaces:
        print("[!] No active network interfaces found.")
        sys.exit(1)

    print(f"[*] Active interfaces:")
    for iface in interfaces:
        print(f"    - {iface['name']}: {iface['ip']}/{iface['prefix']}")

    local_ip = interfaces[0]["ip"]
    all_devices = []

    # scan through each interface with arp-scan
    for iface in interfaces:
        subnet = get_subnet(iface["ip"], iface["prefix"])
        print(f"[*] ARP scanning on {iface['name']} ({subnet})...")
        devices = scan_arp(interface=iface["name"])
        print(f"    found {len(devices)} device(s)")
        all_devices.extend(devices)

    # if arp-scan found nothing, fallback to nmap on first interface
    if not all_devices:
        subnet = get_subnet(interfaces[0]["ip"], interfaces[0]["prefix"])
        print(f"[*] ARP scan empty, trying nmap ping scan on {subnet}...")
        all_devices = scan_nmap_ping(subnet)

    # deduplicate
    all_devices = merge_devices(all_devices)

    print_devices(all_devices, local_ip)

    if all_devices and ("--save" in sys.argv or "-s" in sys.argv):
        save_results(all_devices)

    if "--loop" in sys.argv:
        try:
            interval = 30
            for i, arg in enumerate(sys.argv):
                if arg == "--loop" and i + 1 < len(sys.argv):
                    try:
                        interval = int(sys.argv[i + 1])
                    except ValueError:
                        pass
            print(f"[*] Continuous mode: rescanning every {interval}s (Ctrl+C to stop)\n")
            while True:
                time.sleep(interval)
                print(f"\n[*] Rescanning... {datetime.now().strftime('%H:%M:%S')}")
                rescan = []
                for iface in interfaces:
                    rescan.extend(scan_arp(interface=iface["name"]))
                if not rescan:
                    subnet = get_subnet(interfaces[0]["ip"], interfaces[0]["prefix"])
                    rescan = scan_nmap_ping(subnet)
                rescan = merge_devices(rescan)
                print_devices(rescan, local_ip)
        except KeyboardInterrupt:
            print("\n[*] Stopped.")


if __name__ == "__main__":
    main()
