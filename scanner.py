#!/usr/bin/env python3
"""LAN scanner + port scanner + vuln checker for Raspberry Pi 3B+ / Kali Linux."""

import subprocess
import sys
import json
import re
import socket
import time
import xml.etree.ElementTree as ET
from datetime import datetime


# ──────────────────────────────────────────────────────────────
# Network discovery
# ──────────────────────────────────────────────────────────────

def get_interfaces():
    """Get all active network interfaces with their IPs."""
    interfaces = []
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
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
    parts = ip.split(".")
    if prefix <= 24:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/{prefix}"
    return f"{ip}/{prefix}"


def scan_arp(interface=None):
    """ARP scan using arp-scan."""
    devices = []
    try:
        cmd = ["arp-scan", "--localnet", "--retry=3", "--timeout=1000"]
        if interface:
            cmd += ["-I", interface]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
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
    """Ping scan using nmap (fallback)."""
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
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ""


def merge_devices(all_devices):
    seen = {}
    for d in all_devices:
        key = d["mac"]
        if key not in seen or seen[key]["vendor"] == "":
            seen[key] = d
    return list(seen.values())


# ──────────────────────────────────────────────────────────────
# Port scanning + service detection
# ──────────────────────────────────────────────────────────────

def scan_ports(ip, mode="quick"):
    """
    Scan ports on a target IP using nmap.
    Modes:
      quick  — top 100 ports, service version detection
      full   — all 65535 ports (slow!)
      vuln   — top 1000 ports + version detection + vuln scripts
    """
    ports = []

    if mode == "quick":
        cmd = ["nmap", "-sV", "-T4", "--top-ports", "100", "-oX", "-", ip]
        timeout = 120
    elif mode == "full":
        cmd = ["nmap", "-sV", "-T4", "-p-", "-oX", "-", ip]
        timeout = 600
    elif mode == "vuln":
        cmd = ["nmap", "-sV", "-T4", "--top-ports", "1000",
               "--script", "vulners,vuln",
               "-oX", "-", ip]
        timeout = 300
    else:
        cmd = ["nmap", "-sV", "-T4", "--top-ports", "100", "-oX", "-", ip]
        timeout = 120

    try:
        print(f"    nmap {mode} scan on {ip}...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        root = ET.fromstring(result.stdout)

        for host in root.findall(".//host"):
            for port_el in host.findall(".//port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_id = port_el.get("portid")
                protocol = port_el.get("protocol", "tcp")

                service_el = port_el.find("service")
                service_name = ""
                service_version = ""
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")
                    extra = service_el.get("extrainfo", "")
                    service_version = " ".join(filter(None, [product, version, extra]))

                # collect vuln script output
                vulns = []
                for script in port_el.findall(".//script"):
                    script_id = script.get("id", "")
                    output = script.get("output", "").strip()
                    if output and ("VULNERABLE" in output or "vulners" in script_id):
                        vulns.append({"script": script_id, "output": output})

                ports.append({
                    "port": int(port_id),
                    "protocol": protocol,
                    "service": service_name,
                    "version": service_version,
                    "vulns": vulns,
                })

    except FileNotFoundError:
        print("[!] nmap not found.")
    except subprocess.TimeoutExpired:
        print(f"[!] Port scan timed out for {ip}")
    except ET.ParseError:
        print(f"[!] Failed to parse nmap output for {ip}")

    return ports


# ──────────────────────────────────────────────────────────────
# Display
# ──────────────────────────────────────────────────────────────

def print_devices(devices, local_ip=None):
    if not devices:
        print("\n[!] No devices found.")
        return

    for d in devices:
        d["hostname"] = resolve_hostname(d["ip"])

    devices.sort(key=lambda d: tuple(int(p) for p in d["ip"].split(".")))

    print(f"\n{'='*74}")
    print(f" Found {len(devices)} device(s) on the local network")
    print(f"{'='*74}")
    print(f" {'#':<4}{'IP Address':<18}{'MAC Address':<20}{'Vendor/Hostname'}")
    print(f" {'-'*2:<4}{'-'*16:<18}{'-'*17:<20}{'-'*33}")

    for i, d in enumerate(devices, 1):
        name = d["hostname"] or d["vendor"] or "Unknown"
        marker = " <-- you" if d["ip"] == local_ip else ""
        print(f" {i:<4}{d['ip']:<18}{d['mac']:<20}{name}{marker}")

    print(f"{'='*74}")
    return devices


def print_ports(ip, ports):
    if not ports:
        print(f"\n[*] No open ports found on {ip}")
        return

    has_vulns = any(p["vulns"] for p in ports)

    print(f"\n{'='*74}")
    print(f" Open ports on {ip}")
    print(f"{'='*74}")
    print(f" {'Port':<10}{'Service':<16}{'Version'}")
    print(f" {'-'*7:<10}{'-'*14:<16}{'-'*40}")

    for p in ports:
        print(f" {p['port']}/{p['protocol']:<6} {p['service']:<16}{p['version']}")

    if has_vulns:
        print(f"\n{'-'*74}")
        print(f" VULNERABILITIES:")
        print(f"{'-'*74}")
        for p in ports:
            for v in p["vulns"]:
                print(f"\n [!] Port {p['port']}/{p['protocol']} — {v['script']}")
                for line in v["output"].splitlines()[:20]:
                    print(f"     {line}")

    print(f"{'='*74}\n")


def save_results(data, filename="scan_results.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Results saved to {filename}")


# ──────────────────────────────────────────────────────────────
# Interactive menu
# ──────────────────────────────────────────────────────────────

def pick_targets(devices):
    """Let user pick which devices to scan."""
    print("\n[?] Which targets to port-scan?")
    print("    a = all devices")
    print("    1,3,5 = specific device numbers")
    print("    q = skip port scan")
    choice = input("\n    > ").strip().lower()

    if choice == "q":
        return []
    if choice == "a":
        return [d["ip"] for d in devices]

    targets = []
    for part in choice.split(","):
        try:
            idx = int(part.strip()) - 1
            if 0 <= idx < len(devices):
                targets.append(devices[idx]["ip"])
        except ValueError:
            pass
    return targets


def pick_scan_mode():
    """Let user pick scan depth."""
    print("\n[?] Scan mode:")
    print("    1 = quick  (top 100 ports + service versions)")
    print("    2 = full   (all 65535 ports + versions — slow!)")
    print("    3 = vuln   (top 1000 ports + vulnerability scripts)")
    choice = input("\n    > ").strip()

    modes = {"1": "quick", "2": "full", "3": "vuln"}
    return modes.get(choice, "quick")


# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

def main():
    print("\n[*] PENSTATION — LAN Scanner & Vulnerability Checker")
    print(f"[*] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    interfaces = get_interfaces()
    if not interfaces:
        print("[!] No active network interfaces found.")
        sys.exit(1)

    print(f"[*] Active interfaces:")
    for iface in interfaces:
        print(f"    - {iface['name']}: {iface['ip']}/{iface['prefix']}")

    local_ips = {iface["ip"] for iface in interfaces}
    local_ip = interfaces[0]["ip"]

    # ── Phase 1: Device discovery ──
    all_devices = []
    for iface in interfaces:
        subnet = get_subnet(iface["ip"], iface["prefix"])
        print(f"[*] ARP scanning on {iface['name']} ({subnet})...")
        devices = scan_arp(interface=iface["name"])
        print(f"    found {len(devices)} device(s)")
        all_devices.extend(devices)

    if not all_devices:
        subnet = get_subnet(interfaces[0]["ip"], interfaces[0]["prefix"])
        print(f"[*] ARP scan empty, trying nmap ping scan on {subnet}...")
        all_devices = scan_nmap_ping(subnet)

    all_devices = merge_devices(all_devices)
    # exclude our own IPs from targets
    all_devices = [d for d in all_devices if d["ip"] not in local_ips]

    sorted_devices = print_devices(all_devices, local_ip)

    if not sorted_devices:
        return

    # ── Phase 2: Port scan ──
    if "--scan" in sys.argv:
        # non-interactive: scan all with quick mode
        targets = [d["ip"] for d in sorted_devices]
        mode = "quick"
        for i, arg in enumerate(sys.argv):
            if arg == "--mode" and i + 1 < len(sys.argv):
                mode = sys.argv[i + 1]
    else:
        targets = pick_targets(sorted_devices)
        if not targets:
            print("[*] Done.")
            return
        mode = pick_scan_mode()

    print(f"\n[*] Starting {mode} port scan on {len(targets)} target(s)...\n")

    all_results = {
        "scan_time": datetime.now().isoformat(),
        "mode": mode,
        "targets": [],
    }

    for ip in targets:
        ports = scan_ports(ip, mode)
        print_ports(ip, ports)

        all_results["targets"].append({
            "ip": ip,
            "ports": ports,
        })

    # save if requested
    if "--save" in sys.argv or "-s" in sys.argv:
        save_results(all_results)

    open_count = sum(len(t["ports"]) for t in all_results["targets"])
    vuln_count = sum(
        len(v) for t in all_results["targets"]
        for p in t["ports"] for v in [p["vulns"]] if v
    )

    print(f"[*] Scan complete: {open_count} open port(s), {vuln_count} vuln(s) found")
    print(f"[*] Done.")


if __name__ == "__main__":
    main()
