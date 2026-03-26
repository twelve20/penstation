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
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from brute import check_default_creds, print_cred_results

print_lock = Lock()


def tprint(*args, **kwargs):
    """Thread-safe print."""
    with print_lock:
        print(*args, **kwargs)


# ──────────────────────────────────────────────────────────────
# Network discovery
# ──────────────────────────────────────────────────────────────

def get_interfaces():
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
# Port scanning + service detection (optimized)
# ──────────────────────────────────────────────────────────────

def parse_nmap_ports(xml_output):
    """Parse open ports from nmap XML output."""
    ports = []
    root = ET.fromstring(xml_output)
    for port_el in root.findall(".//port"):
        state = port_el.find("state")
        if state is not None and state.get("state") == "open":
            ports.append(port_el.get("portid"))
    return ports


def parse_nmap_services(xml_output, vuln_results=None):
    """Parse services and versions from nmap XML output."""
    if vuln_results is None:
        vuln_results = {}
    ports = []
    root = ET.fromstring(xml_output)
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
            vulns = vuln_results.get(port_id, [])
            ports.append({
                "port": int(port_id),
                "protocol": protocol,
                "service": service_name,
                "version": service_version,
                "vulns": vulns,
            })
    return ports


def scan_vuln_port(ip, port):
    """Scan a single port for vulns (used in parallel)."""
    try:
        vuln_cmd = ["nmap", "-Pn", "-sV", "-T4",
                    "-p", port,
                    "--script", "vulners",
                    "-oX", "-", ip]
        vresult = subprocess.run(vuln_cmd, capture_output=True, text=True, timeout=90)
        vroot = ET.fromstring(vresult.stdout)
        vulns = []
        for port_el in vroot.findall(".//port"):
            for script in port_el.findall(".//script"):
                script_id = script.get("id", "")
                output = script.get("output", "").strip()
                if output:
                    vulns.append({"script": script_id, "output": output})
        return port, vulns
    except (subprocess.TimeoutExpired, ET.ParseError):
        return port, []


def scan_ports(ip, mode="quick"):
    """
    Multi-pass scan:
      Pass 1: fast SYN scan (-sS) to find open ports
      Pass 2: version detection (-sV) only on open ports
      Pass 3: vuln scripts in parallel (vuln mode only)
    """
    # Pass 1: fast SYN scan
    if mode == "quick":
        discovery_cmd = ["nmap", "-Pn", "-sS", "-T4", "--max-retries=2",
                         "--top-ports", "100", "-oX", "-", ip]
        timeout1 = 60
    elif mode == "full":
        discovery_cmd = ["nmap", "-Pn", "-sS", "-T4", "--max-retries=2",
                         "-p-", "-oX", "-", ip]
        timeout1 = 300
    else:  # vuln
        discovery_cmd = ["nmap", "-Pn", "-sS", "-T4", "--max-retries=2",
                         "--top-ports", "1000", "-oX", "-", ip]
        timeout1 = 120

    try:
        tprint(f"    [{ip}] pass 1: finding open ports...")
        result = subprocess.run(discovery_cmd, capture_output=True, text=True, timeout=timeout1)
        open_ports = parse_nmap_ports(result.stdout)

        if not open_ports:
            tprint(f"    [{ip}] no open ports found")
            return []

        port_list = ",".join(open_ports)
        tprint(f"    [{ip}] found {len(open_ports)} open port(s): {port_list}")

        # Pass 2: version detection (lower intensity = faster)
        intensity = "3" if mode == "quick" else "5"
        version_cmd = ["nmap", "-Pn", "-sV", "-T4",
                       "--version-intensity", intensity,
                       "-p", port_list, "-oX", "-", ip]

        tprint(f"    [{ip}] pass 2: detecting services...")
        result = subprocess.run(version_cmd, capture_output=True, text=True, timeout=180)

        # Pass 3 (vuln mode): parallel vuln scanning
        vuln_results = {}
        if mode == "vuln":
            tprint(f"    [{ip}] pass 3: checking vulns ({len(open_ports)} ports in parallel)...")
            with ThreadPoolExecutor(max_workers=min(len(open_ports), 4)) as pool:
                futures = {pool.submit(scan_vuln_port, ip, p): p for p in open_ports}
                for future in as_completed(futures):
                    port, vulns = future.result()
                    if vulns:
                        vuln_results[port] = vulns
                        tprint(f"      port {port} — {len(vulns)} finding(s)")

        return parse_nmap_services(result.stdout, vuln_results)

    except FileNotFoundError:
        tprint("[!] nmap not found.")
    except subprocess.TimeoutExpired:
        tprint(f"[!] Port scan timed out for {ip}")
    except ET.ParseError:
        tprint(f"[!] Failed to parse nmap output for {ip}")

    return []


def scan_single_target(ip, scan_mode, check_creds):
    """Scan one target (ports + vulns + creds). Used for parallel execution."""
    ports = scan_ports(ip, scan_mode)

    cred_findings = []
    if ports:
        if check_creds:
            tprint(f"    [{ip}] checking default credentials...")
            cred_findings = check_default_creds(ip, ports)
        else:
            dangerous = [p for p in ports if p["service"] in ("telnet", "ftp") or p["port"] in (23, 21)]
            if dangerous:
                tprint(f"    [{ip}] checking telnet/ftp for default passwords...")
                cred_findings = check_default_creds(ip, dangerous)

    return {"ip": ip, "ports": ports, "credentials": cred_findings}


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
    print("\n[?] Scan mode:")
    print("    1 = quick  (top 100 ports + service versions)")
    print("    2 = full   (all 65535 ports + versions — slow!)")
    print("    3 = vuln   (top 1000 ports + vulnerability scripts)")
    print("    4 = vuln+creds (vuln scan + default password check)")
    choice = input("\n    > ").strip()

    modes = {"1": "quick", "2": "full", "3": "vuln", "4": "vuln+creds"}
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
    all_devices = [d for d in all_devices if d["ip"] not in local_ips]

    sorted_devices = print_devices(all_devices, local_ip)

    if not sorted_devices:
        return

    # ── Phase 2: Port scan ──
    if "--scan" in sys.argv:
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

    check_creds = mode == "vuln+creds"
    scan_mode = "vuln" if check_creds else mode

    start_time = time.time()
    print(f"\n[*] Starting {mode} scan on {len(targets)} target(s)...\n")

    all_results = {
        "scan_time": datetime.now().isoformat(),
        "mode": mode,
        "targets": [],
    }

    # parallel scanning: each target in its own thread
    if len(targets) > 1:
        # limit workers on RPi (4 cores, limited RAM)
        max_workers = min(len(targets), 3)
        print(f"[*] Scanning {len(targets)} targets in parallel ({max_workers} workers)\n")

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(scan_single_target, ip, scan_mode, check_creds): ip
                for ip in targets
            }
            for future in as_completed(futures):
                result = future.result()
                # print results sequentially for readability
                with print_lock:
                    print_ports(result["ip"], result["ports"])
                    if result["credentials"]:
                        print_cred_results(result["ip"], result["credentials"])
                all_results["targets"].append(result)
    else:
        # single target, no threading overhead
        for ip in targets:
            result = scan_single_target(ip, scan_mode, check_creds)
            print_ports(result["ip"], result["ports"])
            if result["credentials"]:
                print_cred_results(result["ip"], result["credentials"])
            all_results["targets"].append(result)

    elapsed = time.time() - start_time

    if "--save" in sys.argv or "-s" in sys.argv:
        save_results(all_results)

    open_count = sum(len(t["ports"]) for t in all_results["targets"])
    vuln_count = sum(
        len(v) for t in all_results["targets"]
        for p in t["ports"] for v in [p["vulns"]] if v
    )
    cred_count = sum(len(t["credentials"]) for t in all_results["targets"])

    print(f"[*] Scan complete in {elapsed:.1f}s:")
    print(f"    {open_count} open port(s)")
    print(f"    {vuln_count} vulnerability(-ies)")
    print(f"    {cred_count} credential issue(s)")
    print(f"[*] Done.")


if __name__ == "__main__":
    main()
