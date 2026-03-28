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
print("\n[1/12] Python")
v = sys.version_info
check(f"Python {v.major}.{v.minor}.{v.micro}", v.major == 3 and v.minor >= 6,
      "Need Python 3.6+" if v.major != 3 or v.minor < 6 else "")

# ── 2. Required system tools ──
print("\n[2/12] System tools")

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
print("\n[3/12] Privileges")
is_root = os.geteuid() == 0
check("Running as root", is_root,
      "Run with sudo for ARP scanning" if not is_root else "")

# ── 4. Network interfaces ──
print("\n[4/12] Network")

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
print("\n[5/12] Modules")

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
    ("fingerprint", "fingerprint_device"),
    ("fingerprint", "classify_by_mac"),
    ("fingerprint", "classify_by_ports"),
    ("fingerprint", "classify_by_hostname"),
    ("fingerprint", "detect_os"),
    ("fingerprint", "detect_os_nmap"),
    ("fingerprint", "guess_os_from_banners"),
    ("fingerprint", "guess_os_from_ports"),
    ("traceroute", "run_traceroute"),
    ("traceroute", "parse_traceroute_output"),
    ("traceroute", "resolve_target"),
    ("watchdog", "load_known_devices"),
    ("watchdog", "save_known_devices"),
    ("watchdog", "find_new_devices"),
    ("watchdog", "scan_current_devices"),
    ("watchdog", "run_watchdog"),
    ("wifi_monitor", "scan_wifi"),
    ("wifi_monitor", "find_wifi_interface"),
    ("wifi_monitor", "parse_airodump_csv"),
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
print("\n[6/12] ARP scan (live test)")

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
print("\n[7/12] Nmap port scan (localhost test)")

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

# fingerprint module tests
print("\n[8/12] Device fingerprinting")
try:
    from fingerprint import fingerprint_device, classify_by_mac, classify_by_ports

    # test router by vendor
    fp = fingerprint_device({"ip": "192.168.1.1", "mac": "50:ff:20:30:59:71",
                             "vendor": "Keenetic Limited", "hostname": ""})
    check(f"Keenetic → {fp['type']}", fp["type"] == "router")

    # test PC by vendor
    fp = fingerprint_device({"ip": "192.168.1.36", "mac": "00:d8:61:bb:ba:61",
                             "vendor": "Micro-Star INTL CO., LTD.", "hostname": ""})
    check(f"Micro-Star → {fp['type']}", fp["type"] == "pc")

    # test phone by randomized MAC
    fp = fingerprint_device({"ip": "192.168.1.39", "mac": "8a:69:d1:fa:e2:46",
                             "vendor": "(Unknown: locally administered)", "hostname": ""})
    check(f"Random MAC → {fp['type']}", fp["type"] == "phone")

    # test router by ports (DNS + HTTP + telnet)
    router_ports = [
        {"port": 23, "service": "telnet", "version": ""},
        {"port": 53, "service": "domain", "version": ""},
        {"port": 80, "service": "http", "version": ""},
        {"port": 443, "service": "https", "version": ""},
    ]
    fp = fingerprint_device({"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff",
                             "vendor": "", "hostname": ""}, router_ports)
    check(f"Ports 23+53+80+443 → {fp['type']}", fp["type"] == "router")

    # test PC by Windows port
    pc_ports = [{"port": 5357, "service": "http", "version": "Microsoft HTTPAPI"}]
    fp = fingerprint_device({"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:ff",
                             "vendor": "", "hostname": ""}, pc_ports)
    check(f"Port 5357 Microsoft → {fp['type']}", fp["type"] == "pc")

    # test hostname classification
    fp = fingerprint_device({"ip": "10.0.0.3", "mac": "aa:bb:cc:dd:ee:ff",
                             "vendor": "", "hostname": "iPhone-de-Juan"})
    check(f"Hostname 'iPhone-de-Juan' → {fp['type']}", fp["type"] == "phone")

    # test Raspberry Pi
    fp = fingerprint_device({"ip": "10.0.0.4", "mac": "b8:27:eb:fd:b9:15",
                             "vendor": "Raspberry Pi Foundation", "hostname": ""})
    check(f"Raspberry Pi → {fp['type']}", fp["type"] == "sbc")

except Exception as e:
    check("Fingerprint module", False, str(e))

# OS detection tests (banner-based, no network needed)
print("\n[9/12] OS detection")
try:
    from fingerprint import guess_os_from_banners, guess_os_from_ports, detect_os

    # Windows from banner
    win_ports = [{"port": 5357, "service": "http", "version": "Microsoft HTTPAPI httpd 2.0 SSDP/UPnP"}]
    os_info = guess_os_from_banners(win_ports)
    check(f"Banner 'Microsoft HTTPAPI' → {os_info['os_family']}",
          os_info and os_info["os_family"] == "Windows")

    # Linux from banner
    linux_ports = [{"port": 22, "service": "ssh", "version": "OpenSSH 8.9 Ubuntu"}]
    os_info = guess_os_from_banners(linux_ports)
    check(f"Banner 'OpenSSH Ubuntu' → {os_info['os_family']}",
          os_info and os_info["os_family"] == "Linux")

    # KeeneticOS from banner
    keen_ports = [{"port": 23, "service": "telnet", "version": "KeeneticOS version 4.03"}]
    os_info = guess_os_from_banners(keen_ports)
    check(f"Banner 'KeeneticOS' → {os_info['os_family']}",
          os_info and os_info["os_family"] == "KeeneticOS")

    # Windows from ports
    os_info = guess_os_from_ports([{"port": 445, "service": "microsoft-ds", "version": ""}])
    check(f"Port 445 → {os_info['os_family']}",
          os_info and os_info["os_family"] == "Windows")

    # Linux from ports
    os_info = guess_os_from_ports([{"port": 22, "service": "ssh", "version": ""}])
    check(f"Port 22 only → {os_info['os_family']}",
          os_info and os_info["os_family"] == "Linux")

    # detect_os without nmap -O (banner only)
    os_info = detect_os("127.0.0.1", win_ports, use_nmap_os=False)
    check(f"detect_os(nmap=off) → {os_info['os_family']}",
          os_info["os_family"] == "Windows")

except Exception as e:
    check("OS detection", False, str(e))

# ── 10. Traceroute ──
print("\n[10/12] Traceroute")

# check traceroute binary
try:
    r = subprocess.run(["traceroute", "--version"], capture_output=True, text=True, timeout=5)
    ver = r.stdout.splitlines()[0] if r.stdout else r.stderr.splitlines()[0] if r.stderr else "?"
    check("traceroute installed", True, ver.strip()[:60])
except FileNotFoundError:
    warn("traceroute not installed", "Install: sudo apt install traceroute")

# test parse_traceroute_output with sample data
try:
    from traceroute import parse_traceroute_output, resolve_target

    sample = """traceroute to 8.8.8.8 (8.8.8.8), 30 hops max
 1  gateway (192.168.1.1)  1.234 ms  1.456 ms  1.789 ms
 2  10.0.0.1 (10.0.0.1)  12.345 ms  11.234 ms  13.456 ms
 3  * * *
 4  dns.google (8.8.8.8)  20.123 ms  19.456 ms  21.789 ms"""

    hops = parse_traceroute_output(sample)
    check(f"Parse traceroute: {len(hops)} hops", len(hops) == 4)
    check(f"Hop 1 IP: {hops[0]['ip']}", hops[0]["ip"] == "192.168.1.1")
    check(f"Hop 3 timeout: {hops[2]['timeout']}", hops[2]["timeout"] is True)
    check(f"Hop 1 RTTs: {len(hops[0]['rtts'])}", len(hops[0]["rtts"]) == 3)

    # test resolve_target
    ip, host = resolve_target("8.8.8.8")
    check(f"Resolve 8.8.8.8 → {ip}", ip == "8.8.8.8")

except Exception as e:
    check("Traceroute module", False, str(e))

# ── 11. Watchdog ──
print("\n[11/12] Network watchdog")

try:
    from watchdog import load_known_devices, save_known_devices, find_new_devices
    import tempfile

    # test save/load round-trip
    test_path = tempfile.mktemp(suffix=".json")
    test_known = {
        "aa:bb:cc:dd:ee:ff": {
            "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.100",
            "vendor": "TestVendor", "label": "TestDevice",
            "first_seen": "2026-01-01", "approved": True,
        }
    }
    save_known_devices(test_known, test_path)
    loaded = load_known_devices(test_path)
    check(f"Save/load known devices", "aa:bb:cc:dd:ee:ff" in loaded)
    os.remove(test_path)

    # test find_new_devices
    current = [
        {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.100", "vendor": "Old"},
        {"mac": "11:22:33:44:55:66", "ip": "192.168.1.200", "vendor": "New"},
    ]
    new = find_new_devices(current, test_known)
    check(f"Find new devices: {len(new)} new", len(new) == 1 and new[0]["mac"] == "11:22:33:44:55:66")

    # test empty file handling
    empty = load_known_devices("/tmp/nonexistent_penstation_test.json")
    check("Load nonexistent file → empty dict", empty == {})

except Exception as e:
    check("Watchdog module", False, str(e))

# ── 12. Wi-Fi monitor ──
print("\n[12/12] Wi-Fi monitor")

# check aircrack-ng
try:
    subprocess.run(["airmon-ng", "--help"], capture_output=True, text=True, timeout=5)
    check("aircrack-ng installed", True)
except FileNotFoundError:
    warn("aircrack-ng not installed", "Install: sudo apt install aircrack-ng")

# test CSV parsing with sample data
try:
    from wifi_monitor import parse_airodump_csv
    import tempfile

    sample_csv = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2026-03-26 12:00:00, 2026-03-26 12:01:00, 6, 54, WPA2, CCMP, PSK, -45, 100, 50, 0.0.0.0, 10, TestNetwork,
11:22:33:44:55:66, 2026-03-26 12:00:00, 2026-03-26 12:01:00, 1, 54, OPN, , , -70, 50, 10, 0.0.0.0, 8, OpenWifi,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
DE:AD:BE:EF:00:01, 2026-03-26 12:00:00, 2026-03-26 12:01:00, -55, 100, AA:BB:CC:DD:EE:FF, TestNetwork
"""
    tmp = tempfile.mktemp(suffix=".csv")
    with open(tmp, "w") as f:
        f.write(sample_csv)

    aps, clients = parse_airodump_csv(tmp)
    os.remove(tmp)

    check(f"Parse airodump CSV: {len(aps)} AP(s)", len(aps) == 2)
    check(f"AP ESSID: {aps[0]['essid']}", aps[0]["essid"] in ("TestNetwork", "OpenWifi"))
    check(f"Parse clients: {len(clients)} client(s)", len(clients) == 1)
    check(f"Client MAC: {clients[0]['mac']}", clients[0]["mac"] == "DE:AD:BE:EF:00:01")

except Exception as e:
    check("Wi-Fi monitor module", False, str(e))

# check for Wi-Fi interfaces
try:
    from wifi_monitor import find_wifi_interface
    wifi_iface = find_wifi_interface()
    if wifi_iface:
        check(f"Wi-Fi adapter found: {wifi_iface}", True)
    else:
        warn("No external Wi-Fi adapter found", "Plug in TP-Link TL-WN722N for Wi-Fi monitoring")
except Exception as e:
    warn("Wi-Fi interface check", str(e))


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
