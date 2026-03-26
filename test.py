#!/usr/bin/env python3
"""
PENSTATION — self-test script.
Checks that all components work correctly on this system.
Run: sudo python3 test.py
"""

import subprocess
import sys
import socket
import importlib
import os
import time

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
WARN = "\033[93m[WARN]\033[0m"
INFO = "\033[94m[INFO]\033[0m"

passed = 0
failed = 0
warned = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  {PASS} {name}")
    else:
        failed += 1
        print(f"  {FAIL} {name}")
    if detail:
        print(f"         {detail}")


def warn(name, detail=""):
    global warned
    warned += 1
    print(f"  {WARN} {name}")
    if detail:
        print(f"         {detail}")


def info(name, detail=""):
    print(f"  {INFO} {name}")
    if detail:
        print(f"         {detail}")


# ──────────────────────────────────────────────────────────────
print("\n" + "="*60)
print(" PENSTATION self-test")
print("="*60)

# ── 1. Python version ──
print("\n[1/7] Python")
v = sys.version_info
check(f"Python {v.major}.{v.minor}.{v.micro}", v.major == 3 and v.minor >= 6,
      "Need Python 3.6+" if v.major != 3 or v.minor < 6 else "")

# ── 2. Required system tools ──
print("\n[2/7] System tools")

tools = {
    "nmap": ["nmap", "--version"],
    "arp-scan": ["arp-scan", "--version"],
}
optional_tools = {
    "hydra": ["hydra", "-h"],
}

for name, cmd in tools.items():
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        version = r.stdout.splitlines()[0] if r.stdout else r.stderr.splitlines()[0] if r.stderr else "?"
        check(f"{name} installed", True, version.strip()[:60])
    except FileNotFoundError:
        check(f"{name} installed", False, f"Install: sudo apt install {name}")

for name, cmd in optional_tools.items():
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        check(f"{name} installed (optional)", True)
    except FileNotFoundError:
        warn(f"{name} not installed (optional)", f"Install: sudo apt install {name}")

# ── 3. Root privileges ──
print("\n[3/7] Privileges")
is_root = os.geteuid() == 0
check("Running as root", is_root,
      "Run with sudo for ARP scanning" if not is_root else "")

# ── 4. Network interfaces ──
print("\n[4/7] Network")

try:
    from scanner import get_interfaces, get_subnet
    interfaces = get_interfaces()
    check(f"Found {len(interfaces)} interface(s)", len(interfaces) > 0)
    for iface in interfaces:
        info(f"  {iface['name']}: {iface['ip']}/{iface['prefix']}")
except Exception as e:
    check("Import scanner module", False, str(e))
    interfaces = []

# check internet connectivity
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    check(f"Network reachable (local IP: {local_ip})", True)
except Exception as e:
    check("Network reachable", False, str(e))

# ── 5. Module imports ──
print("\n[5/7] Modules")

modules_to_test = [
    ("scanner", "get_interfaces"),
    ("scanner", "scan_arp"),
    ("scanner", "scan_ports"),
    ("scanner", "merge_devices"),
    ("scanner", "parse_nmap_ports"),
    ("scanner", "parse_nmap_services"),
    ("scanner", "scan_single_target"),
    ("brute", "check_default_creds"),
    ("brute", "check_telnet"),
    ("brute", "check_ssh"),
    ("brute", "check_ftp"),
    ("brute", "check_http"),
    ("brute", "print_cred_results"),
    ("brute", "DEFAULT_CREDS"),
]

for mod_name, func_name in modules_to_test:
    try:
        mod = importlib.import_module(mod_name)
        obj = getattr(mod, func_name)
        check(f"{mod_name}.{func_name}", True)
    except ImportError as e:
        check(f"{mod_name}.{func_name}", False, f"Import error: {e}")
    except AttributeError:
        check(f"{mod_name}.{func_name}", False, "Function not found")

# ── 6. ARP scan test ──
print("\n[6/7] ARP scan (live test)")

if is_root and interfaces:
    try:
        from scanner import scan_arp
        iface = interfaces[0]
        start = time.time()
        devices = scan_arp(interface=iface["name"])
        elapsed = time.time() - start
        check(f"ARP scan on {iface['name']}: {len(devices)} device(s) in {elapsed:.1f}s",
              len(devices) > 0,
              "No devices found — check network" if not devices else "")
        for d in devices[:5]:
            info(f"  {d['ip']} — {d['mac']} — {d['vendor'][:40]}")
        if len(devices) > 5:
            info(f"  ... and {len(devices)-5} more")
    except Exception as e:
        check("ARP scan", False, str(e))
else:
    warn("ARP scan skipped", "Need root + active interface")

# ── 7. Nmap port scan test (scan localhost) ──
print("\n[7/7] Nmap port scan (localhost test)")

if is_root:
    try:
        from scanner import parse_nmap_ports
        start = time.time()
        result = subprocess.run(
            ["nmap", "-Pn", "-sS", "-T4", "--top-ports", "20",
             "-oX", "-", "127.0.0.1"],
            capture_output=True, text=True, timeout=30
        )
        ports = parse_nmap_ports(result.stdout)
        elapsed = time.time() - start
        check(f"Nmap SYN scan localhost: {len(ports)} port(s) in {elapsed:.1f}s", True)
        for p in ports:
            info(f"  port {p}")
    except subprocess.TimeoutExpired:
        check("Nmap scan localhost", False, "Timed out")
    except Exception as e:
        check("Nmap scan localhost", False, str(e))
else:
    warn("Nmap SYN scan skipped", "Need root")

# nmap XML parsing test with fake data
print()
try:
    from scanner import parse_nmap_ports, parse_nmap_services
    fake_xml = """<?xml version="1.0"?>
    <nmaprun>
      <host><ports>
        <port protocol="tcp" portid="22">
          <state state="open"/>
          <service name="ssh" product="OpenSSH" version="8.9"/>
        </port>
        <port protocol="tcp" portid="80">
          <state state="open"/>
          <service name="http" product="nginx" version="1.18"/>
        </port>
        <port protocol="tcp" portid="443">
          <state state="closed"/>
        </port>
      </ports></host>
    </nmaprun>"""

    open_ports = parse_nmap_ports(fake_xml)
    check(f"XML parse open ports: {open_ports}", open_ports == ["22", "80"])

    services = parse_nmap_services(fake_xml)
    check(f"XML parse services: {len(services)} entries",
          len(services) == 2 and services[0]["service"] == "ssh")

except Exception as e:
    check("Nmap XML parsing", False, str(e))

# brute module cred database check
try:
    from brute import DEFAULT_CREDS
    for svc in ["telnet", "ssh", "ftp", "http"]:
        check(f"Default creds for {svc}: {len(DEFAULT_CREDS[svc])} entries",
              len(DEFAULT_CREDS[svc]) > 0)
except Exception as e:
    check("Default creds database", False, str(e))


# ──────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────
print("\n" + "="*60)
total = passed + failed
print(f" Results: {passed}/{total} passed, {failed} failed, {warned} warnings")

if failed == 0:
    print(f" {PASS} All checks passed! PENSTATION is ready.")
else:
    print(f" {FAIL} {failed} check(s) failed. Fix issues above.")

print("="*60 + "\n")

sys.exit(0 if failed == 0 else 1)
