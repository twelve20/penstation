#!/usr/bin/env python3
"""Device fingerprinting — identify device type and OS by MAC, ports, banners, nmap OS detection."""

import subprocess
import re
import xml.etree.ElementTree as ET


# ──────────────────────────────────────────────────────────────
# MAC OUI → device type mapping
# ──────────────────────────────────────────────────────────────

# Format: (oui_prefix, vendor_keyword) → (device_type, icon)
# OUI = first 3 octets of MAC address

ROUTER_VENDORS = {
    "keenetic", "tp-link", "tplink", "d-link", "dlink", "netgear", "asus",
    "linksys", "mikrotik", "ubiquiti", "cisco", "huawei", "zyxel", "tenda",
    "xiaomi router", "mercusys", "netis", "ruijie", "aruba", "juniper",
    "fortinet", "sonicwall", "watchguard", "pfsense", "openwrt",
}

PHONE_VENDORS = {
    "apple", "samsung", "huawei", "xiaomi", "oppo", "vivo", "oneplus",
    "realme", "motorola", "nokia", "sony mobile", "lg electronics",
    "google", "honor", "zte", "meizu", "tecno", "infinix", "itel",
    "nothing", "fairphone", "poco",
}

IOT_VENDORS = {
    "espressif", "tuya", "shenzhen", "sonoff", "yeelight", "broadlink",
    "amazon", "ring", "nest", "ecobee", "philips hue", "lifx",
    "tp-link smart", "wyze", "aqara", "zigbee", "ewelink",
    "hikvision", "dahua", "reolink", "eufy", "blink",
}

PC_VENDORS = {
    "micro-star", "msi", "dell", "lenovo", "hewlett", "hp ", "acer",
    "gigabyte", "asrock", "intel", "amd", "nvidia",
    "realtek", "qualcomm atheros",
}

MEDIA_VENDORS = {
    "roku", "fire tv", "chromecast", "apple tv", "nvidia shield",
    "playstation", "xbox", "nintendo", "valve", "steam",
}

PRINTER_VENDORS = {
    "brother", "canon", "epson", "ricoh", "xerox", "lexmark",
    "kyocera", "konica", "sharp",
}

SERVER_VENDORS = {
    "supermicro", "ibm", "oracle", "vmware",
}


# ──────────────────────────────────────────────────────────────
# Port-based fingerprinting
# ──────────────────────────────────────────────────────────────

# (port_set_present, service_names) → device_type
ROUTER_PORTS = {53, 80, 443, 23, 1900}      # DNS + web + telnet + UPnP
PRINTER_PORTS = {631, 9100, 515}              # IPP, RAW, LPD
SERVER_PORTS = {22, 80, 443, 3306, 5432, 8080, 8443}
IOT_PORTS = {8883, 1883}                      # MQTT
MEDIA_PORTS = {8008, 8009, 8443, 9080}        # Chromecast, Roku


def classify_by_mac(mac, vendor):
    """Classify device by MAC address and vendor string."""
    if not vendor or vendor == "N/A":
        # check if locally administered MAC (random)
        first_byte = int(mac.split(":")[0], 16)
        if first_byte & 0x02:
            return "phone", "Randomized MAC (likely phone)"
        return "unknown", ""

    vendor_lower = vendor.lower()

    for kw in ROUTER_VENDORS:
        if kw in vendor_lower:
            return "router", vendor
    for kw in PHONE_VENDORS:
        if kw in vendor_lower:
            return "phone", vendor
    for kw in IOT_VENDORS:
        if kw in vendor_lower:
            return "iot", vendor
    for kw in PC_VENDORS:
        if kw in vendor_lower:
            return "pc", vendor
    for kw in MEDIA_VENDORS:
        if kw in vendor_lower:
            return "media", vendor
    for kw in PRINTER_VENDORS:
        if kw in vendor_lower:
            return "printer", vendor
    for kw in SERVER_VENDORS:
        if kw in vendor_lower:
            return "server", vendor

    # Raspberry Pi
    if "raspberry" in vendor_lower:
        return "sbc", vendor

    return "unknown", vendor


def classify_by_ports(open_ports):
    """Classify device by open port pattern."""
    if not open_ports:
        return None

    port_nums = {p["port"] for p in open_ports}
    services = {p["service"].lower() for p in open_ports if p.get("service")}
    versions = " ".join(p.get("version", "") for p in open_ports).lower()

    # Router: has DNS(53) + web(80/443) or UPnP(1900)
    if (53 in port_nums and (80 in port_nums or 443 in port_nums)):
        return "router"
    if 1900 in port_nums and "miniupnp" in versions:
        return "router"

    # Printer
    if port_nums & PRINTER_PORTS:
        return "printer"

    # IoT (MQTT)
    if port_nums & IOT_PORTS:
        return "iot"

    # Windows PC
    if "microsoft" in versions or 5357 in port_nums or 3389 in port_nums:
        return "pc"
    if 135 in port_nums or 445 in port_nums:
        return "pc"

    # Linux server/PC
    if 22 in port_nums and (80 in port_nums or 8080 in port_nums):
        return "server"

    # Media
    if port_nums & MEDIA_PORTS:
        return "media"

    # phone with high random port (UPnP/DLNA)
    if len(port_nums) == 1:
        p = list(port_nums)[0]
        if p > 49000 and any(s in services for s in ("tcpwrapped", "upnp")):
            return "phone"

    return None


def classify_by_hostname(hostname):
    """Classify by hostname patterns."""
    if not hostname:
        return None

    h = hostname.lower()

    phone_patterns = ["iphone", "ipad", "android", "galaxy", "pixel",
                      "huawei", "xiaomi", "redmi", "oneplus", "poco"]
    for p in phone_patterns:
        if p in h:
            return "phone"

    pc_patterns = ["desktop", "laptop", "pc", "workstation", "-pc",
                   "macbook", "imac", "mac-pro"]
    for p in pc_patterns:
        if p in h:
            return "pc"

    server_patterns = ["server", "nas", "proxmox", "esxi", "docker"]
    for p in server_patterns:
        if p in h:
            return "server"

    printer_patterns = ["printer", "print", "brother", "canon", "epson"]
    for p in printer_patterns:
        if p in h:
            return "printer"

    if "raspberrypi" in h or "raspberry" in h:
        return "sbc"

    return None


# ──────────────────────────────────────────────────────────────
# OS detection
# ──────────────────────────────────────────────────────────────

def detect_os_nmap(ip):
    """
    Run nmap OS detection (-O) on a target.
    Returns dict with os_name, os_family, os_accuracy, os_vendor.
    Requires root.
    """
    try:
        result = subprocess.run(
            ["nmap", "-Pn", "-O", "--osscan-limit", "--max-os-tries=1",
             "-T4", "-oX", "-", ip],
            capture_output=True, text=True, timeout=60
        )
        root = ET.fromstring(result.stdout)

        best_match = None
        best_accuracy = 0

        for osmatch in root.findall(".//osmatch"):
            accuracy = int(osmatch.get("accuracy", "0"))
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                name = osmatch.get("name", "")

                # get OS class info
                osclass = osmatch.find("osclass")
                family = ""
                vendor = ""
                osgen = ""
                if osclass is not None:
                    family = osclass.get("osfamily", "")
                    vendor = osclass.get("vendor", "")
                    osgen = osclass.get("osgen", "")

                best_match = {
                    "os_name": name,
                    "os_family": family,
                    "os_vendor": vendor,
                    "os_gen": osgen,
                    "os_accuracy": accuracy,
                }

        return best_match or {}

    except (subprocess.TimeoutExpired, ET.ParseError, FileNotFoundError):
        return {}


def guess_os_from_banners(open_ports):
    """
    Guess OS from service version banners (no extra scan needed).
    Works even when nmap -O can't determine the OS.
    """
    if not open_ports:
        return None

    all_versions = " ".join(
        f"{p.get('service', '')} {p.get('version', '')}" for p in open_ports
    ).lower()

    # Windows indicators
    if any(kw in all_versions for kw in [
        "microsoft", "windows", "iis", "ms-wbt", "msrpc",
        "ssdp/upnp", "httpapi"
    ]):
        # try to extract Windows version
        match = re.search(r"windows\s+([\w\s.]+?)(?:\s|$|;)", all_versions)
        if match:
            return {"os_family": "Windows", "os_name": f"Windows {match.group(1).strip()}",
                    "os_accuracy": 70, "source": "banner"}
        return {"os_family": "Windows", "os_name": "Windows",
                "os_accuracy": 60, "source": "banner"}

    # Linux indicators
    if any(kw in all_versions for kw in [
        "ubuntu", "debian", "centos", "fedora", "red hat", "arch",
        "openssh", "apache", "nginx"
    ]):
        distro = "Linux"
        for d in ["ubuntu", "debian", "centos", "fedora", "red hat", "arch", "kali"]:
            if d in all_versions:
                distro = d.capitalize()
                break
        # try to get version from OpenSSH
        ssh_match = re.search(r"openssh[_ ]([\d.]+p?\d*)\s*(ubuntu|debian)?", all_versions)
        if ssh_match:
            detail = ssh_match.group(2) or ""
            if detail:
                distro = detail.capitalize()
        return {"os_family": "Linux", "os_name": f"Linux ({distro})",
                "os_accuracy": 50, "source": "banner"}

    # macOS
    if any(kw in all_versions for kw in ["macos", "darwin", "apple"]):
        return {"os_family": "macOS", "os_name": "macOS",
                "os_accuracy": 50, "source": "banner"}

    # Keenetic / router firmware
    if "keeneticos" in all_versions:
        match = re.search(r"keeneticos\s+version\s+([\d.]+)", all_versions)
        ver = match.group(1) if match else ""
        return {"os_family": "KeeneticOS", "os_name": f"KeeneticOS {ver}".strip(),
                "os_accuracy": 90, "source": "banner"}

    # MikroTik
    if "routeros" in all_versions or "mikrotik" in all_versions:
        return {"os_family": "RouterOS", "os_name": "MikroTik RouterOS",
                "os_accuracy": 80, "source": "banner"}

    # Android (rare, but sometimes mDNS or DLNA leaks)
    if "android" in all_versions:
        return {"os_family": "Android", "os_name": "Android",
                "os_accuracy": 60, "source": "banner"}

    # iOS
    if "airplay" in all_versions or "apple mobile" in all_versions:
        return {"os_family": "iOS", "os_name": "iOS/iPadOS",
                "os_accuracy": 50, "source": "banner"}

    # FreeBSD
    if "freebsd" in all_versions:
        return {"os_family": "FreeBSD", "os_name": "FreeBSD",
                "os_accuracy": 60, "source": "banner"}

    return None


def guess_os_from_ports(open_ports):
    """
    Last resort: guess OS family from port patterns.
    Low confidence but better than nothing.
    """
    if not open_ports:
        return None

    port_nums = {p["port"] for p in open_ports}

    # strong Windows indicators
    if port_nums & {135, 139, 445, 3389, 5357}:
        return {"os_family": "Windows", "os_name": "Windows (port pattern)",
                "os_accuracy": 40, "source": "ports"}

    # SSH without Windows ports = probably Linux
    if 22 in port_nums and not (port_nums & {135, 445, 3389}):
        return {"os_family": "Linux", "os_name": "Linux (has SSH)",
                "os_accuracy": 30, "source": "ports"}

    return None


# ──────────────────────────────────────────────────────────────
# Main fingerprint function
# ──────────────────────────────────────────────────────────────

DEVICE_LABELS = {
    "router":  "Router/Gateway",
    "pc":      "PC/Laptop",
    "phone":   "Phone/Tablet",
    "iot":     "IoT Device",
    "media":   "Media/Gaming",
    "printer": "Printer",
    "server":  "Server",
    "sbc":     "Single-Board Computer",
    "unknown": "Unknown",
}

DEVICE_ICONS = {
    "router":  "[R]",
    "pc":      "[P]",
    "phone":   "[M]",
    "iot":     "[I]",
    "media":   "[TV]",
    "printer": "[PR]",
    "server":  "[S]",
    "sbc":     "[SBC]",
    "unknown": "[?]",
}


def fingerprint_device(device, open_ports=None):
    """
    Determine device type using all available information.
    Priority: hostname > ports > MAC/vendor

    Args:
        device: dict with ip, mac, vendor, hostname
        open_ports: list of port dicts from scan_ports()

    Returns:
        dict with type, label, icon, confidence, reason
    """
    mac = device.get("mac", "")
    vendor = device.get("vendor", "")
    hostname = device.get("hostname", "")

    # try hostname first (highest confidence)
    hostname_type = classify_by_hostname(hostname)
    if hostname_type:
        return {
            "type": hostname_type,
            "label": DEVICE_LABELS[hostname_type],
            "icon": DEVICE_ICONS[hostname_type],
            "confidence": "high",
            "reason": f"hostname: {hostname}",
        }

    # try port-based classification
    port_type = classify_by_ports(open_ports) if open_ports else None

    # try MAC/vendor classification
    mac_type, mac_detail = classify_by_mac(mac, vendor)

    # combine results
    if port_type and mac_type != "unknown":
        # both agree
        if port_type == mac_type:
            return {
                "type": port_type,
                "label": DEVICE_LABELS[port_type],
                "icon": DEVICE_ICONS[port_type],
                "confidence": "high",
                "reason": f"ports + vendor: {vendor}",
            }
        # ports override MAC (more reliable for network behavior)
        return {
            "type": port_type,
            "label": DEVICE_LABELS[port_type],
            "icon": DEVICE_ICONS[port_type],
            "confidence": "medium",
            "reason": f"ports (vendor suggests {mac_type}: {vendor})",
        }

    if port_type:
        return {
            "type": port_type,
            "label": DEVICE_LABELS[port_type],
            "icon": DEVICE_ICONS[port_type],
            "confidence": "medium",
            "reason": "port pattern",
        }

    if mac_type != "unknown":
        return {
            "type": mac_type,
            "label": DEVICE_LABELS[mac_type],
            "icon": DEVICE_ICONS[mac_type],
            "confidence": "medium" if mac_detail else "low",
            "reason": f"vendor: {mac_detail}" if mac_detail else "MAC OUI",
        }

    # locally administered MAC = probably phone
    if mac:
        first_byte = int(mac.split(":")[0], 16)
        if first_byte & 0x02:
            return {
                "type": "phone",
                "label": DEVICE_LABELS["phone"],
                "icon": DEVICE_ICONS["phone"],
                "confidence": "low",
                "reason": "randomized MAC address",
            }

    return {
        "type": "unknown",
        "label": DEVICE_LABELS["unknown"],
        "icon": DEVICE_ICONS["unknown"],
        "confidence": "low",
        "reason": "no identifying features",
    }


def detect_os(ip, open_ports=None, use_nmap_os=True):
    """
    Combined OS detection using multiple methods.
    Priority: nmap -O > banner analysis > port guessing.

    Args:
        ip: target IP
        open_ports: list of port dicts (from scan_ports)
        use_nmap_os: whether to run nmap -O (requires root, slower)

    Returns:
        dict with os_name, os_family, os_accuracy, source
    """
    # 1. Try banner analysis first (free — uses existing scan data)
    banner_os = guess_os_from_banners(open_ports)

    # 2. If banner gave high confidence or nmap -O disabled, use that
    if banner_os and banner_os["os_accuracy"] >= 80:
        return banner_os

    # 3. Try nmap -O (accurate but slow)
    nmap_os = {}
    if use_nmap_os:
        nmap_os = detect_os_nmap(ip)
        if nmap_os and nmap_os.get("os_accuracy", 0) > 0:
            nmap_os["source"] = "nmap -O"
            # if nmap is more confident, use it
            if not banner_os or nmap_os["os_accuracy"] > banner_os["os_accuracy"]:
                return nmap_os

    # 4. Banner result (medium confidence)
    if banner_os:
        return banner_os

    # 5. Port-based guess (low confidence)
    port_os = guess_os_from_ports(open_ports)
    if port_os:
        return port_os

    return {"os_name": "Unknown", "os_family": "Unknown",
            "os_accuracy": 0, "source": "none"}
