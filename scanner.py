#!/usr/bin/env python3
"""Simple LAN device scanner for Raspberry Pi 3B+ with Kali Linux."""

import subprocess
import sys
import json
import re
import socket
import time
from datetime import datetime


def get_local_ip():
    """Get the local IP address and subnet."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def get_subnet(ip):
    """Derive /24 subnet from IP (e.g. 192.168.1.0/24)."""
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def scan_arp(subnet):
    """ARP scan using arp-scan (fast, requires root)."""
    devices = []
    try:
        result = subprocess.run(
            ["arp-scan", "--localnet", "--retry=2"],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            match = re.match(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)", line
            )
            if match:
                devices.append({
                    "ip": match.group(1),
                    "mac": match.group(2),
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
            ["nmap", "-sn", subnet],
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

            mac_match = re.search(r"MAC Address: ([0-9A-F:]{17})\s*(.*)", line)
            if mac_match:
                current_mac = mac_match.group(1)
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


def print_devices(devices):
    """Pretty-print discovered devices."""
    if not devices:
        print("\n[!] No devices found.")
        return

    # resolve hostnames
    for d in devices:
        d["hostname"] = resolve_hostname(d["ip"])

    # sort by IP
    devices.sort(key=lambda d: tuple(int(p) for p in d["ip"].split(".")))

    print(f"\n{'='*70}")
    print(f" Found {len(devices)} device(s) on the local network")
    print(f"{'='*70}")
    print(f" {'IP Address':<18}{'MAC Address':<20}{'Vendor/Hostname'}")
    print(f" {'-'*16:<18}{'-'*17:<20}{'-'*30}")

    for d in devices:
        name = d["hostname"] or d["vendor"] or "Unknown"
        print(f" {d['ip']:<18}{d['mac']:<20}{name}")

    print(f"{'='*70}\n")


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

    local_ip = get_local_ip()
    if not local_ip:
        print("[!] Could not determine local IP. Check network connection.")
        sys.exit(1)

    subnet = get_subnet(local_ip)
    print(f"[*] Local IP: {local_ip}")
    print(f"[*] Scanning subnet: {subnet}")

    # try arp-scan first (faster), fall back to nmap
    print("[*] Running ARP scan...")
    devices = scan_arp(subnet)

    if not devices:
        print("[*] ARP scan returned no results, trying nmap ping scan...")
        devices = scan_nmap_ping(subnet)

    print_devices(devices)

    if devices and ("--save" in sys.argv or "-s" in sys.argv):
        save_results(devices)

    if "--loop" in sys.argv:
        try:
            interval = 30
            for i, arg in enumerate(sys.argv):
                if arg == "--loop" and i + 1 < len(sys.argv):
                    interval = int(sys.argv[i + 1])
            print(f"[*] Continuous mode: rescanning every {interval}s (Ctrl+C to stop)\n")
            while True:
                time.sleep(interval)
                print(f"\n[*] Rescanning... {datetime.now().strftime('%H:%M:%S')}")
                devices = scan_arp(subnet) or scan_nmap_ping(subnet)
                print_devices(devices)
        except KeyboardInterrupt:
            print("\n[*] Stopped.")


if __name__ == "__main__":
    main()
