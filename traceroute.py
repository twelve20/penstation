#!/usr/bin/env python3
"""Traceroute module — trace network path to external hosts."""

import subprocess
import re
import socket


def resolve_target(target):
    """Resolve hostname to IP. Returns (ip, hostname) or raises."""
    try:
        ip = socket.gethostbyname(target)
        return ip, target if ip != target else ""
    except socket.gaierror:
        raise ValueError(f"Cannot resolve: {target}")


def run_traceroute(target, method="icmp", max_hops=30):
    """
    Run traceroute to target.
    method: icmp, udp, tcp
    Returns list of hop dicts.
    """
    if method == "icmp":
        cmd = ["traceroute", "-I", "-m", str(max_hops), "-w", "2", target]
    elif method == "tcp":
        cmd = ["traceroute", "-T", "-p", "80", "-m", str(max_hops), "-w", "2", target]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", "2", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        return parse_traceroute_output(result.stdout)
    except FileNotFoundError:
        # fallback to nmap
        return run_nmap_traceroute(target)
    except subprocess.TimeoutExpired:
        print("[!] Traceroute timed out")
        return []


def parse_traceroute_output(stdout):
    """Parse traceroute text output into structured hops."""
    hops = []
    for line in stdout.splitlines():
        # match: " 1  hostname (ip)  1.234 ms  ..."  or  " 1  ip  1.234 ms ..."
        hop_match = re.match(r"\s*(\d+)\s+(.*)", line)
        if not hop_match:
            continue

        hop_num = int(hop_match.group(1))
        rest = hop_match.group(2).strip()

        # all timeouts
        if rest == "* * *":
            hops.append({
                "hop": hop_num,
                "ip": "*",
                "hostname": "",
                "rtts": [],
                "timeout": True,
            })
            continue

        # extract IP and hostname
        ip = ""
        hostname = ""
        rtts = []

        # pattern: hostname (ip) rtt ms rtt ms ...
        addr_match = re.match(r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+(.*)", rest)
        if addr_match:
            hostname = addr_match.group(1)
            ip = addr_match.group(2)
            rtt_part = addr_match.group(3)
        else:
            # pattern: ip  rtt ms rtt ms ...
            addr_match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+(.*)", rest)
            if addr_match:
                ip = addr_match.group(1)
                rtt_part = addr_match.group(2)
            else:
                rtt_part = rest

        # extract RTTs
        for rtt_match in re.finditer(r"([\d.]+)\s*ms", rtt_part):
            rtts.append(float(rtt_match.group(1)))

        if ip or rtts:
            hops.append({
                "hop": hop_num,
                "ip": ip or "*",
                "hostname": hostname if hostname != ip else "",
                "rtts": rtts,
                "timeout": False,
            })

    return hops


def run_nmap_traceroute(target):
    """Fallback traceroute using nmap."""
    import xml.etree.ElementTree as ET
    hops = []
    try:
        result = subprocess.run(
            ["nmap", "-Pn", "--traceroute", "-oX", "-", target],
            capture_output=True, text=True, timeout=60
        )
        root = ET.fromstring(result.stdout)
        for hop in root.findall(".//hop"):
            hop_num = int(hop.get("ttl", "0"))
            ip = hop.get("ipaddr", "*")
            hostname = hop.get("host", "")
            rtt = float(hop.get("rtt", "0"))
            hops.append({
                "hop": hop_num,
                "ip": ip,
                "hostname": hostname if hostname != ip else "",
                "rtts": [rtt] if rtt > 0 else [],
                "timeout": False,
            })
    except (subprocess.TimeoutExpired, ET.ParseError, FileNotFoundError):
        pass
    return hops


def print_traceroute(hops, target):
    """Display traceroute results."""
    if not hops:
        print(f"\n[!] No traceroute data for {target}")
        return

    print(f"\n{'='*74}")
    print(f" Traceroute to {target} ({len(hops)} hops)")
    print(f"{'='*74}")
    print(f" {'Hop':<6}{'IP Address':<18}{'Hostname':<28}{'RTT'}")
    print(f" {'-'*3:<6}{'-'*16:<18}{'-'*26:<28}{'-'*12}")

    for h in hops:
        if h["timeout"]:
            print(f" {h['hop']:<6}{'*':<18}{'(timeout)':<28}{'*'}")
        else:
            avg_rtt = f"{sum(h['rtts'])/len(h['rtts']):.1f} ms" if h["rtts"] else "?"
            name = h["hostname"][:26] or ""
            print(f" {h['hop']:<6}{h['ip']:<18}{name:<28}{avg_rtt}")

    print(f"{'='*74}\n")


def interactive_traceroute():
    """Interactive traceroute menu."""
    print("\n[?] Enter target (IP or hostname):")
    target = input("    > ").strip()
    if not target:
        return None

    try:
        ip, hostname = resolve_target(target)
        print(f"[*] Target: {target} ({ip})")
    except ValueError as e:
        print(f"[!] {e}")
        return None

    print("\n[?] Method:")
    print("    1 = ICMP (default, most reliable)")
    print("    2 = UDP")
    print("    3 = TCP port 80 (bypasses ICMP-blocking firewalls)")
    choice = input("    > ").strip()
    methods = {"1": "icmp", "2": "udp", "3": "tcp"}
    method = methods.get(choice, "icmp")

    print(f"\n[*] Running {method.upper()} traceroute to {target}...")
    hops = run_traceroute(target, method)
    print_traceroute(hops, target)

    return {"target": target, "ip": ip, "method": method, "hops": hops}
