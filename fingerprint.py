#!/usr/bin/env python3
"""Device fingerprinting — identify device type by MAC OUI, open ports, banners."""


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
