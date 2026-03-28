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
import re
import time
import tempfile
import json

# ── Colors ──
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
WARN = "\033[93m[WARN]\033[0m"
INFO = "\033[94m[INFO]\033[0m"
SECT = "\033[96m"  # cyan for section headers
RESET = "\033[0m"
BOLD = "\033[1m"

passed = 0
failed = 0
warned = 0
section_results = []  # (name, passed, failed, warned)


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
    return ok


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


def section(num, total, name):
    global passed, failed, warned
    # save previous section stats
    print(f"\n{SECT}{BOLD}[{num}/{total}] {name}{RESET}")
    return passed, failed, warned


def section_end(name, prev_p, prev_f, prev_w):
    """Track per-section results."""
    sp = passed - prev_p
    sf = failed - prev_f
    sw = warned - prev_w
    section_results.append((name, sp, sf, sw))


TOTAL_SECTIONS = 14

# ══════════════════════════════════════════════════════════════
print(f"\n{'='*64}")
print(f" {BOLD}PENSTATION — полная проверка системы{RESET}")
print(f"{'='*64}")

# ── 1. Python ──
p, f, w = section(1, TOTAL_SECTIONS, "Python")
v = sys.version_info
check(f"Python {v.major}.{v.minor}.{v.micro}", v.major == 3 and v.minor >= 6,
      "Нужен Python 3.6+" if v.major != 3 or v.minor < 6 else "")
section_end("Python", p, f, w)

# ── 2. Системные утилиты ──
p, f, w = section(2, TOTAL_SECTIONS, "Системные утилиты")

required_tools = {
    "nmap":       (["nmap", "--version"],      "sudo apt install nmap"),
    "arp-scan":   (["arp-scan", "--version"],   "sudo apt install arp-scan"),
    "traceroute": (["traceroute", "--version"], "sudo apt install traceroute"),
}
optional_tools = {
    "hydra":       (["hydra", "-h"],               "sudo apt install hydra"),
    "aircrack-ng": (["airmon-ng", "--help"],        "sudo apt install aircrack-ng"),
    "iw":          (["iw", "--version"],            "sudo apt install iw"),
    "iwconfig":    (["iwconfig", "--version"],      "sudo apt install wireless-tools"),
}

for name, (cmd, install) in required_tools.items():
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        ver = r.stdout.splitlines()[0] if r.stdout else r.stderr.splitlines()[0] if r.stderr else "?"
        check(f"{name}", True, ver.strip()[:60])
    except FileNotFoundError:
        check(f"{name}", False, f"Установи: {install}")

for name, (cmd, install) in optional_tools.items():
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        check(f"{name} (опционально)", True)
    except FileNotFoundError:
        warn(f"{name} не установлен", f"Установи: {install}")

section_end("Утилиты", p, f, w)

# ── 3. Привилегии ──
p, f, w = section(3, TOTAL_SECTIONS, "Привилегии")
is_root = os.geteuid() == 0
check("Запуск от root", is_root,
      "Запусти: sudo python3 test.py" if not is_root else "")
section_end("Привилегии", p, f, w)

# ── 4. Сеть ──
p, f, w = section(4, TOTAL_SECTIONS, "Сетевые интерфейсы")

interfaces = []
try:
    from scanner import get_interfaces, get_subnet
    interfaces = get_interfaces()
    check(f"Найдено интерфейсов: {len(interfaces)}", len(interfaces) > 0)
    for iface in interfaces:
        info(f"  {iface['name']}: {iface['ip']}/{iface['prefix']}")
except Exception as e:
    check("Импорт scanner", False, str(e))

# интернет
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    check(f"Интернет доступен (IP: {local_ip})", True)
except Exception as e:
    check("Интернет доступен", False, str(e))

# DNS
try:
    socket.gethostbyname("google.com")
    check("DNS работает", True)
except Exception:
    check("DNS работает", False, "Не удалось разрешить google.com")

section_end("Сеть", p, f, w)

# ── 5. Импорт модулей ──
p, f, w = section(5, TOTAL_SECTIONS, "Импорт модулей")

modules_to_test = [
    ("scanner",       ["get_interfaces", "scan_arp", "scan_ports", "merge_devices",
                       "parse_nmap_ports", "parse_nmap_services", "scan_single_target"]),
    ("brute",         ["check_default_creds", "check_telnet", "check_ssh",
                       "check_ftp", "check_http", "DEFAULT_CREDS"]),
    ("fingerprint",   ["fingerprint_device", "classify_by_mac", "classify_by_ports",
                       "classify_by_hostname", "detect_os", "detect_os_nmap",
                       "guess_os_from_banners", "guess_os_from_ports"]),
    ("traceroute",    ["run_traceroute", "parse_traceroute_output", "resolve_target",
                       "run_nmap_traceroute", "print_traceroute"]),
    ("watchdog",      ["load_known_devices", "save_known_devices", "find_new_devices",
                       "find_disappeared", "scan_current_devices", "run_watchdog"]),
    ("wifi_monitor",  ["scan_wifi", "find_wifi_interface", "parse_airodump_csv",
                       "enable_monitor_mode", "disable_monitor_mode",
                       "get_monitor_interfaces", "_verify_monitor_mode"]),
]

for mod_name, funcs in modules_to_test:
    try:
        mod = importlib.import_module(mod_name)
        missing = [f for f in funcs if not hasattr(mod, f)]
        if not missing:
            check(f"{mod_name} — все {len(funcs)} функций", True)
        else:
            check(f"{mod_name} — не найдены: {', '.join(missing)}", False)
    except ImportError as e:
        check(f"{mod_name}", False, f"Ошибка импорта: {e}")

section_end("Модули", p, f, w)

# ── 6. ARP сканирование ──
p, f, w = section(6, TOTAL_SECTIONS, "ARP сканирование (live)")

if is_root and interfaces:
    try:
        from scanner import scan_arp
        iface = interfaces[0]
        start = time.time()
        devices = scan_arp(interface=iface["name"])
        elapsed = time.time() - start
        check(f"ARP скан {iface['name']}: {len(devices)} устр. за {elapsed:.1f}s",
              len(devices) > 0,
              "Нет устройств — проверь сеть" if not devices else "")
        for d in devices[:5]:
            info(f"  {d['ip']} — {d['mac']} — {d['vendor'][:40]}")
        if len(devices) > 5:
            info(f"  ... ещё {len(devices)-5}")
    except Exception as e:
        check("ARP скан", False, str(e))
else:
    warn("ARP скан пропущен", "Нужен root + активный интерфейс")

section_end("ARP скан", p, f, w)

# ── 7. Nmap ──
p, f, w = section(7, TOTAL_SECTIONS, "Nmap сканирование")

# XML parsing test
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
    check(f"XML парсинг портов: {open_ports}", open_ports == ["22", "80"])

    services = parse_nmap_services(fake_xml)
    check(f"XML парсинг сервисов: {len(services)} шт",
          len(services) == 2 and services[0]["service"] == "ssh")

    check("SSH версия из XML",
          services[0]["version"] == "OpenSSH 8.9")
    check("HTTP сервер из XML",
          services[1]["version"] == "nginx 1.18")

except Exception as e:
    check("Nmap XML парсинг", False, str(e))

# live nmap scan on localhost
if is_root:
    try:
        start = time.time()
        result = subprocess.run(
            ["nmap", "-Pn", "-sS", "-T4", "--top-ports", "20",
             "-oX", "-", "127.0.0.1"],
            capture_output=True, text=True, timeout=30
        )
        ports = parse_nmap_ports(result.stdout)
        elapsed = time.time() - start
        check(f"Nmap SYN localhost: {len(ports)} порт(ов) за {elapsed:.1f}s", True)
    except subprocess.TimeoutExpired:
        check("Nmap SYN localhost", False, "Таймаут")
    except Exception as e:
        check("Nmap SYN localhost", False, str(e))
else:
    warn("Nmap SYN пропущен", "Нужен root")

section_end("Nmap", p, f, w)

# ── 8. Проверка паролей ──
p, f, w = section(8, TOTAL_SECTIONS, "Модуль брутфорса")

try:
    from brute import DEFAULT_CREDS, SERVICE_CHECKERS

    for svc in ["telnet", "ssh", "ftp", "http"]:
        creds = DEFAULT_CREDS.get(svc, [])
        check(f"Словарь {svc}: {len(creds)} пар(а)", len(creds) > 0)

    check(f"SERVICE_CHECKERS: {len(SERVICE_CHECKERS)} сервисов",
          len(SERVICE_CHECKERS) >= 4)

    # проверяем что чекеры — вызываемые функции
    for svc_name, checker in SERVICE_CHECKERS.items():
        check(f"Чекер {svc_name} — callable", callable(checker))

except Exception as e:
    check("Модуль brute", False, str(e))

section_end("Брутфорс", p, f, w)

# ── 9. Фингерпринтинг устройств ──
p, f, w = section(9, TOTAL_SECTIONS, "Фингерпринтинг устройств")

try:
    from fingerprint import fingerprint_device, classify_by_mac, classify_by_ports, classify_by_hostname

    tests = [
        # (описание, device_dict, ports, expected_type)
        ("Keenetic по вендору → router",
         {"ip": "192.168.1.1", "mac": "50:ff:20:30:59:71",
          "vendor": "Keenetic Limited", "hostname": ""},
         None, "router"),

        ("Micro-Star по вендору → pc",
         {"ip": "192.168.1.36", "mac": "00:d8:61:bb:ba:61",
          "vendor": "Micro-Star INTL CO., LTD.", "hostname": ""},
         None, "pc"),

        ("Рандомный MAC → phone",
         {"ip": "192.168.1.39", "mac": "8a:69:d1:fa:e2:46",
          "vendor": "(Unknown: locally administered)", "hostname": ""},
         None, "phone"),

        ("Raspberry Pi → sbc",
         {"ip": "10.0.0.4", "mac": "b8:27:eb:fd:b9:15",
          "vendor": "Raspberry Pi Foundation", "hostname": ""},
         None, "sbc"),

        ("Hostname 'iPhone-de-Juan' → phone",
         {"ip": "10.0.0.3", "mac": "aa:bb:cc:dd:ee:ff",
          "vendor": "", "hostname": "iPhone-de-Juan"},
         None, "phone"),

        ("Порты DNS+HTTP+Telnet → router",
         {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff",
          "vendor": "", "hostname": ""},
         [{"port": 23, "service": "telnet", "version": ""},
          {"port": 53, "service": "domain", "version": ""},
          {"port": 80, "service": "http", "version": ""},
          {"port": 443, "service": "https", "version": ""}],
         "router"),

        ("Порт 5357 Microsoft → pc",
         {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:ff",
          "vendor": "", "hostname": ""},
         [{"port": 5357, "service": "http", "version": "Microsoft HTTPAPI"}],
         "pc"),

        ("Порт 9100 → printer",
         {"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff",
          "vendor": "", "hostname": ""},
         [{"port": 9100, "service": "jetdirect", "version": ""},
          {"port": 631, "service": "ipp", "version": ""}],
         "printer"),
    ]

    for desc, device, ports, expected in tests:
        fp = fingerprint_device(device, ports)
        check(f"{desc} = {fp['type']}", fp["type"] == expected)

except Exception as e:
    check("Фингерпринтинг", False, str(e))

section_end("Фингерпринтинг", p, f, w)

# ── 10. Определение ОС ──
p, f, w = section(10, TOTAL_SECTIONS, "Определение ОС")

try:
    from fingerprint import guess_os_from_banners, guess_os_from_ports, detect_os

    banner_tests = [
        ("Microsoft HTTPAPI → Windows",
         [{"port": 5357, "service": "http", "version": "Microsoft HTTPAPI httpd 2.0 SSDP/UPnP"}],
         "Windows"),
        ("OpenSSH Ubuntu → Linux",
         [{"port": 22, "service": "ssh", "version": "OpenSSH 8.9 Ubuntu"}],
         "Linux"),
        ("KeeneticOS → KeeneticOS",
         [{"port": 23, "service": "telnet", "version": "KeeneticOS version 4.03"}],
         "KeeneticOS"),
        ("MikroTik → RouterOS",
         [{"port": 8291, "service": "winbox", "version": "MikroTik RouterOS"}],
         "RouterOS"),
    ]

    for desc, ports, expected in banner_tests:
        os_info = guess_os_from_banners(ports)
        check(f"Баннер: {desc}",
              os_info and os_info["os_family"] == expected,
              f"Получили: {os_info}" if os_info and os_info["os_family"] != expected else "")

    port_tests = [
        ("Порт 445 → Windows",
         [{"port": 445, "service": "microsoft-ds", "version": ""}],
         "Windows"),
        ("Порт 22 → Linux",
         [{"port": 22, "service": "ssh", "version": ""}],
         "Linux"),
    ]

    for desc, ports, expected in port_tests:
        os_info = guess_os_from_ports(ports)
        check(f"Порты: {desc}",
              os_info and os_info["os_family"] == expected)

    # detect_os без nmap -O (только баннеры)
    win_ports = [{"port": 5357, "service": "http",
                  "version": "Microsoft HTTPAPI httpd 2.0 SSDP/UPnP"}]
    os_info = detect_os("127.0.0.1", win_ports, use_nmap_os=False)
    check(f"detect_os(nmap=off) → {os_info['os_family']}",
          os_info["os_family"] == "Windows")

except Exception as e:
    check("Определение ОС", False, str(e))

section_end("ОС", p, f, w)

# ── 11. Трассировка маршрутов ──
p, f, w = section(11, TOTAL_SECTIONS, "Трассировка маршрутов")

try:
    from traceroute import parse_traceroute_output, resolve_target, run_nmap_traceroute

    sample = """traceroute to 8.8.8.8 (8.8.8.8), 30 hops max
 1  gateway (192.168.1.1)  1.234 ms  1.456 ms  1.789 ms
 2  10.0.0.1 (10.0.0.1)  12.345 ms  11.234 ms  13.456 ms
 3  * * *
 4  dns.google (8.8.8.8)  20.123 ms  19.456 ms  21.789 ms"""

    hops = parse_traceroute_output(sample)
    check(f"Парсинг: {len(hops)} хопов", len(hops) == 4)
    check(f"Хоп 1 IP: {hops[0]['ip']}", hops[0]["ip"] == "192.168.1.1")
    check(f"Хоп 1 hostname: {hops[0]['hostname']}", hops[0]["hostname"] == "gateway")
    check(f"Хоп 3 таймаут", hops[2]["timeout"] is True)
    check(f"Хоп 1 RTT: {len(hops[0]['rtts'])} замеров", len(hops[0]["rtts"]) == 3)
    check(f"Хоп 4 hostname: {hops[3]['hostname']}", hops[3]["hostname"] == "dns.google")

    # средний RTT
    avg = sum(hops[0]["rtts"]) / len(hops[0]["rtts"])
    check(f"Средний RTT хоп 1: {avg:.3f} ms", abs(avg - 1.493) < 0.01)

    # resolve_target
    ip, host = resolve_target("8.8.8.8")
    check(f"Resolve 8.8.8.8 → {ip}", ip == "8.8.8.8")

    try:
        ip, host = resolve_target("google.com")
        check(f"Resolve google.com → {ip}", len(ip) > 0)
    except Exception:
        warn("DNS resolve google.com не сработал")

except Exception as e:
    check("Модуль traceroute", False, str(e))

section_end("Трассировка", p, f, w)

# ── 12. Watchdog (сторож) ──
p, f, w = section(12, TOTAL_SECTIONS, "Сетевой сторож (watchdog)")

try:
    from watchdog import (load_known_devices, save_known_devices,
                          find_new_devices, find_disappeared)

    # save/load round-trip
    test_path = tempfile.mktemp(suffix=".json")
    test_known = {
        "aa:bb:cc:dd:ee:ff": {
            "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.100",
            "vendor": "TestVendor", "label": "TestDevice",
            "first_seen": "2026-01-01", "approved": True,
        },
        "11:22:33:44:55:66": {
            "mac": "11:22:33:44:55:66", "ip": "192.168.1.200",
            "vendor": "Other", "label": "Second",
            "first_seen": "2026-01-01", "approved": True,
        },
    }
    save_known_devices(test_known, test_path)
    loaded = load_known_devices(test_path)
    check("Сохранение/загрузка JSON", len(loaded) == 2)
    check("MAC сохранён", "aa:bb:cc:dd:ee:ff" in loaded)

    # проверяем структуру
    d = loaded["aa:bb:cc:dd:ee:ff"]
    check("Поля устройства",
          d["ip"] == "192.168.1.100" and d["vendor"] == "TestVendor")

    os.remove(test_path)

    # find_new_devices
    current = [
        {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.100", "vendor": "Old"},
        {"mac": "ff:ee:dd:cc:bb:aa", "ip": "192.168.1.250", "vendor": "Intruder"},
    ]
    new = find_new_devices(current, test_known)
    check(f"Новые устройства: {len(new)}", len(new) == 1)
    check(f"MAC нового: {new[0]['mac']}", new[0]["mac"] == "ff:ee:dd:cc:bb:aa")

    # find_disappeared
    disappeared = find_disappeared(current, test_known)
    check(f"Пропавшие: {len(disappeared)}", len(disappeared) == 1)
    check(f"MAC пропавшего: {disappeared[0]['mac']}",
          disappeared[0]["mac"] == "11:22:33:44:55:66")

    # пустой файл
    empty = load_known_devices("/tmp/nonexistent_penstation_test.json")
    check("Несуществующий файл → пустой dict", empty == {})

    # битый JSON
    bad_path = tempfile.mktemp(suffix=".json")
    with open(bad_path, "w") as bf:
        bf.write("{broken json")
    bad = load_known_devices(bad_path)
    check("Битый JSON → пустой dict", bad == {})
    os.remove(bad_path)

except Exception as e:
    check("Модуль watchdog", False, str(e))

section_end("Watchdog", p, f, w)

# ── 13. Wi-Fi монитор — парсинг ──
p, f, w = section(13, TOTAL_SECTIONS, "Wi-Fi монитор — парсинг и функции")

try:
    from wifi_monitor import (parse_airodump_csv, find_wifi_interface,
                              get_monitor_interfaces, _verify_monitor_mode)

    # тест парсинга CSV
    sample_csv = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2026-03-26 12:00:00, 2026-03-26 12:01:00, 6, 54, WPA2, CCMP, PSK, -45, 100, 50, 0.0.0.0, 10, TestNetwork,
11:22:33:44:55:66, 2026-03-26 12:00:00, 2026-03-26 12:01:00, 1, 54, OPN, , , -70, 50, 10, 0.0.0.0, 8, OpenWifi,
99:88:77:66:55:44, 2026-03-26 12:00:00, 2026-03-26 12:01:00, 11, 54, WPA2, CCMP, PSK, -85, 20, 5, 0.0.0.0, 6, WeakSignal,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
DE:AD:BE:EF:00:01, 2026-03-26 12:00:00, 2026-03-26 12:01:00, -55, 100, AA:BB:CC:DD:EE:FF, TestNetwork
CA:FE:BA:BE:00:02, 2026-03-26 12:00:00, 2026-03-26 12:01:00, -65, 50, 11:22:33:44:55:66, OpenWifi
"""
    tmp = tempfile.mktemp(suffix=".csv")
    with open(tmp, "w") as f:
        f.write(sample_csv)

    aps, clients = parse_airodump_csv(tmp)
    os.remove(tmp)

    check(f"Парсинг AP: {len(aps)} точек", len(aps) == 3)
    check(f"Парсинг клиентов: {len(clients)} шт", len(clients) == 2)

    # AP поля
    if aps:
        # APs сортируются по сигналу (strongest first)
        strongest = aps[0]
        check(f"Самая сильная AP: {strongest['power']} dBm",
              strongest["power"] == -45)
        check(f"AP ESSID: {strongest['essid']}", strongest["essid"] == "TestNetwork")
        check(f"AP канал: {strongest['channel']}", strongest["channel"] == "6")
        check(f"AP шифрование: {strongest['encryption']}",
              strongest["encryption"] == "WPA2")
        check(f"AP BSSID: {strongest['bssid']}",
              strongest["bssid"] == "AA:BB:CC:DD:EE:FF")

        weakest = aps[-1]
        check(f"Слабая AP: {weakest['power']} dBm", weakest["power"] == -85)

    # Client поля
    if clients:
        check(f"Клиент MAC: {clients[0]['mac']}",
              clients[0]["mac"] == "DE:AD:BE:EF:00:01")
        check(f"Клиент BSSID: {clients[0]['bssid']}",
              clients[0]["bssid"] == "AA:BB:CC:DD:EE:FF")
        check(f"Клиент сигнал: {clients[0]['power']}",
              clients[0]["power"] == -55)

    # пустой CSV
    empty_tmp = tempfile.mktemp(suffix=".csv")
    with open(empty_tmp, "w") as f:
        f.write("")
    aps_e, clients_e = parse_airodump_csv(empty_tmp)
    os.remove(empty_tmp)
    check("Пустой CSV → 0 AP, 0 клиентов",
          len(aps_e) == 0 and len(clients_e) == 0)

    # несуществующий файл
    aps_n, clients_n = parse_airodump_csv("/tmp/nonexistent.csv")
    check("Несуществующий CSV → 0 AP, 0 клиентов",
          len(aps_n) == 0 and len(clients_n) == 0)

    # _verify_monitor_mode на несуществующем интерфейсе
    result = _verify_monitor_mode("nonexistent_iface_xyz")
    check("_verify_monitor_mode(несущ.) → False", result is False)

except Exception as e:
    check("Wi-Fi парсинг", False, str(e))

section_end("Wi-Fi парсинг", p, f, w)

# ── 14. Wi-Fi монитор — hardware ──
p, f, w = section(14, TOTAL_SECTIONS, "Wi-Fi монитор — оборудование")

try:
    from wifi_monitor import find_wifi_interface, get_monitor_interfaces

    # Wi-Fi адаптер
    wifi_iface = find_wifi_interface()
    if wifi_iface:
        check(f"Wi-Fi адаптер: {wifi_iface}", True)

        # проверяем iwconfig
        try:
            r = subprocess.run(["iwconfig", wifi_iface],
                               capture_output=True, text=True, timeout=5)
            if r.stdout:
                # вытащим режим
                mode_match = re.search(r"Mode:(\S+)", r.stdout)
                mode = mode_match.group(1) if mode_match else "?"
                info(f"  Режим: {mode}")

                freq_match = re.search(r"Frequency[:\s]+([\d.]+ GHz)", r.stdout)
                if freq_match:
                    info(f"  Частота: {freq_match.group(1)}")
        except FileNotFoundError:
            warn("iwconfig недоступен")

        # проверяем поддержку monitor mode
        try:
            import re as re_mod
            # получаем phy
            phy_path = f"/sys/class/net/{wifi_iface}/phy80211/index"
            if os.path.exists(phy_path):
                with open(phy_path) as pf:
                    phy_num = pf.read().strip()
                r = subprocess.run(["iw", f"phy{phy_num}", "info"],
                                   capture_output=True, text=True, timeout=5)
                has_monitor = "monitor" in r.stdout
                check(f"Поддержка monitor mode (phy{phy_num})", has_monitor,
                      "Адаптер не поддерживает monitor mode" if not has_monitor else "")
            else:
                warn("Не удалось определить phy для проверки monitor mode")
        except Exception as e:
            warn(f"Проверка monitor mode: {e}")
    else:
        warn("Wi-Fi адаптер не найден",
             "Подключи TP-Link TL-WN722N или другой адаптер с monitor mode")

    # проверяем активные monitor интерфейсы
    mon = get_monitor_interfaces()
    if mon:
        info(f"  Активные monitor: {', '.join(mon)}")
    else:
        info("  Нет активных monitor интерфейсов (нормально)")

except Exception as e:
    check("Wi-Fi hardware", False, str(e))

section_end("Wi-Fi hardware", p, f, w)


# ══════════════════════════════════════════════════════════════
# Итоги
# ══════════════════════════════════════════════════════════════
print(f"\n{'='*64}")
print(f" {BOLD}ИТОГИ{RESET}")
print(f"{'='*64}")

# per-section summary
for name, sp, sf, sw in section_results:
    if sf > 0:
        status = f"{FAIL}"
    elif sw > 0:
        status = f"{WARN}"
    else:
        status = f"{PASS}"
    parts = []
    if sp > 0:
        parts.append(f"\033[92m{sp} ок\033[0m")
    if sf > 0:
        parts.append(f"\033[91m{sf} ошибок\033[0m")
    if sw > 0:
        parts.append(f"\033[93m{sw} предупр.\033[0m")
    detail = ", ".join(parts) if parts else "—"
    print(f"  {status} {name:<24} {detail}")

total = passed + failed
print(f"\n{'─'*64}")
print(f"  Всего: {BOLD}{passed}/{total}{RESET} пройдено, "
      f"\033[91m{failed}\033[0m ошибок, "
      f"\033[93m{warned}\033[0m предупреждений")

if failed == 0 and warned == 0:
    print(f"\n  {PASS} {BOLD}Всё работает! PENSTATION готов к бою.{RESET}")
elif failed == 0:
    print(f"\n  {PASS} {BOLD}Основные проверки пройдены.{RESET}")
    print(f"  {WARN} Установи недостающие компоненты для полного функционала.")
else:
    print(f"\n  {FAIL} {BOLD}Есть ошибки — исправь их перед использованием.{RESET}")

print(f"{'='*64}\n")

sys.exit(0 if failed == 0 else 1)
