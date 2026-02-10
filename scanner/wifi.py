"""WiFi network manager — scan, connect, disconnect, status."""

import asyncio
import logging
import re

logger = logging.getLogger("penstation.wifi")


async def get_wifi_interface() -> str | None:
    """Detect the primary WiFi interface name."""
    proc = await asyncio.create_subprocess_exec(
        "iw", "dev",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    match = re.search(r"Interface\s+(\S+)", stdout.decode())
    return match.group(1) if match else None


async def get_wifi_status() -> dict:
    """Get current WiFi connection status."""
    iface = await get_wifi_interface()
    if not iface:
        return {"connected": False, "interface": None, "error": "No WiFi interface found"}

    # Try nmcli first (Bookworm default)
    if await _has_nmcli():
        return await _nmcli_status(iface)

    # Fallback to iwconfig/wpa_cli
    return await _wpa_status(iface)


async def scan_networks() -> list[dict]:
    """Scan for available WiFi networks. Returns sorted list by signal strength."""
    iface = await get_wifi_interface()
    if not iface:
        return []

    if await _has_nmcli():
        return await _nmcli_scan(iface)

    return await _iw_scan(iface)


async def connect_network(ssid: str, password: str) -> dict:
    """Connect to a WiFi network."""
    iface = await get_wifi_interface()
    if not iface:
        return {"success": False, "error": "No WiFi interface found"}

    logger.info("Connecting to WiFi: %s", ssid)

    if await _has_nmcli():
        return await _nmcli_connect(ssid, password)

    return await _wpa_connect(iface, ssid, password)


async def disconnect_network() -> dict:
    """Disconnect from current WiFi network."""
    iface = await get_wifi_interface()
    if not iface:
        return {"success": False, "error": "No WiFi interface found"}

    if await _has_nmcli():
        return await _nmcli_disconnect()

    return await _wpa_disconnect(iface)


async def get_saved_networks() -> list[dict]:
    """List saved/known WiFi networks."""
    if await _has_nmcli():
        return await _nmcli_saved()
    return []


async def forget_network(ssid: str) -> dict:
    """Remove a saved WiFi network."""
    if await _has_nmcli():
        return await _nmcli_forget(ssid)
    return {"success": False, "error": "Only supported with NetworkManager"}


# ── Helper: check for nmcli ───────────────────────────────

async def _has_nmcli() -> bool:
    proc = await asyncio.create_subprocess_exec(
        "which", "nmcli",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    return proc.returncode == 0


# ── NetworkManager (nmcli) implementation ─────────────────

async def _nmcli_status(iface: str) -> dict:
    proc = await asyncio.create_subprocess_exec(
        "nmcli", "-t", "-f", "DEVICE,STATE,CONNECTION", "device", "status",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    for line in stdout.decode().strip().split("\n"):
        parts = line.split(":")
        if len(parts) >= 3 and parts[0] == iface:
            connected = parts[1] == "connected"
            ssid = parts[2] if connected else ""
            # Get IP and signal
            ip_addr = ""
            signal = 0
            if connected:
                ip_addr = await _get_ip(iface)
                signal = await _nmcli_signal()
            return {
                "connected": connected,
                "interface": iface,
                "ssid": ssid,
                "ip": ip_addr,
                "signal": signal,
            }
    return {"connected": False, "interface": iface, "ssid": "", "ip": "", "signal": 0}


async def _nmcli_signal() -> int:
    proc = await asyncio.create_subprocess_exec(
        "nmcli", "-t", "-f", "IN-USE,SIGNAL", "device", "wifi", "list",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    for line in stdout.decode().strip().split("\n"):
        if line.startswith("*:"):
            try:
                return int(line.split(":")[1])
            except (ValueError, IndexError):
                pass
    return 0


async def _nmcli_scan(iface: str) -> list[dict]:
    # Force rescan
    await asyncio.create_subprocess_exec(
        "nmcli", "device", "wifi", "rescan",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await asyncio.sleep(2)

    proc = await asyncio.create_subprocess_exec(
        "nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY,BSSID,FREQ", "device", "wifi", "list",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()

    networks = []
    seen_ssids = set()

    for line in stdout.decode().strip().split("\n"):
        if not line.strip():
            continue
        # nmcli -t uses : as separator, but BSSID contains : too
        # Format: IN-USE:SSID:SIGNAL:SECURITY:BSSID:FREQ
        # We parse carefully
        parts = line.split(":")
        if len(parts) < 4:
            continue

        in_use = parts[0] == "*"
        ssid = parts[1]
        if not ssid or ssid in seen_ssids:
            continue
        seen_ssids.add(ssid)

        try:
            signal = int(parts[2])
        except (ValueError, IndexError):
            signal = 0

        security = parts[3] if len(parts) > 3 else ""

        networks.append({
            "ssid": ssid,
            "signal": signal,
            "security": security,
            "connected": in_use,
        })

    # Sort by signal strength (strongest first)
    networks.sort(key=lambda n: n["signal"], reverse=True)
    return networks


async def _nmcli_connect(ssid: str, password: str) -> dict:
    # Check if this is a known network
    saved = await _nmcli_saved()
    is_saved = any(n["ssid"] == ssid for n in saved)

    if is_saved and not password:
        # Reconnect to known network
        proc = await asyncio.create_subprocess_exec(
            "nmcli", "connection", "up", ssid,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    else:
        proc = await asyncio.create_subprocess_exec(
            "nmcli", "device", "wifi", "connect", ssid,
            "password", password,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    stdout, stderr = await proc.communicate()
    output = stdout.decode() + stderr.decode()

    if proc.returncode == 0:
        logger.info("Connected to WiFi: %s", ssid)
        # Wait a moment for IP assignment
        await asyncio.sleep(3)
        status = await get_wifi_status()
        return {"success": True, "ssid": ssid, **status}

    logger.error("WiFi connection failed: %s", output)
    return {"success": False, "error": output.strip()}


async def _nmcli_disconnect() -> dict:
    iface = await get_wifi_interface()
    proc = await asyncio.create_subprocess_exec(
        "nmcli", "device", "disconnect", iface,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode == 0:
        return {"success": True}
    return {"success": False, "error": (stdout.decode() + stderr.decode()).strip()}


async def _nmcli_saved() -> list[dict]:
    proc = await asyncio.create_subprocess_exec(
        "nmcli", "-t", "-f", "NAME,TYPE", "connection", "show",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    networks = []
    for line in stdout.decode().strip().split("\n"):
        parts = line.split(":")
        if len(parts) >= 2 and "wireless" in parts[1]:
            networks.append({"ssid": parts[0]})
    return networks


async def _nmcli_forget(ssid: str) -> dict:
    proc = await asyncio.create_subprocess_exec(
        "nmcli", "connection", "delete", ssid,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode == 0:
        return {"success": True}
    return {"success": False, "error": (stdout.decode() + stderr.decode()).strip()}


# ── wpa_supplicant fallback ───────────────────────────────

async def _wpa_status(iface: str) -> dict:
    proc = await asyncio.create_subprocess_exec(
        "wpa_cli", "-i", iface, "status",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    data = dict(
        line.split("=", 1) for line in stdout.decode().strip().split("\n") if "=" in line
    )
    connected = data.get("wpa_state") == "COMPLETED"
    return {
        "connected": connected,
        "interface": iface,
        "ssid": data.get("ssid", ""),
        "ip": data.get("ip_address", ""),
        "signal": 0,
    }


async def _iw_scan(iface: str) -> list[dict]:
    # Trigger scan
    await asyncio.create_subprocess_exec(
        "ip", "link", "set", iface, "up",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await asyncio.sleep(1)

    proc = await asyncio.create_subprocess_exec(
        "iwlist", iface, "scan",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    output = stdout.decode()

    networks = []
    seen_ssids = set()
    cells = re.split(r"Cell \d+", output)

    for cell in cells:
        ssid_match = re.search(r'ESSID:"([^"]+)"', cell)
        if not ssid_match:
            continue
        ssid = ssid_match.group(1)
        if ssid in seen_ssids:
            continue
        seen_ssids.add(ssid)

        signal = 0
        sig_match = re.search(r"Signal level[=:](-?\d+)", cell)
        if sig_match:
            dbm = int(sig_match.group(1))
            signal = max(0, min(100, 2 * (dbm + 100)))  # Convert dBm to %

        quality_match = re.search(r"Quality[=:](\d+)/(\d+)", cell)
        if quality_match:
            signal = int(int(quality_match.group(1)) / int(quality_match.group(2)) * 100)

        security = "Open"
        if "WPA2" in cell:
            security = "WPA2"
        elif "WPA" in cell:
            security = "WPA"
        elif "WEP" in cell:
            security = "WEP"

        networks.append({
            "ssid": ssid,
            "signal": signal,
            "security": security,
            "connected": False,
        })

    networks.sort(key=lambda n: n["signal"], reverse=True)
    return networks


async def _wpa_connect(iface: str, ssid: str, password: str) -> dict:
    # Generate wpa_supplicant config block
    proc = await asyncio.create_subprocess_exec(
        "wpa_passphrase", ssid, password,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    network_block = stdout.decode()

    # Append to wpa_supplicant.conf
    wpa_conf = "/etc/wpa_supplicant/wpa_supplicant.conf"
    try:
        with open(wpa_conf, "a") as f:
            f.write("\n" + network_block)
    except PermissionError:
        return {"success": False, "error": "Permission denied writing wpa_supplicant.conf"}

    # Reconfigure
    proc = await asyncio.create_subprocess_exec(
        "wpa_cli", "-i", iface, "reconfigure",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()

    # Wait for connection
    await asyncio.sleep(5)
    status = await _wpa_status(iface)
    if status["connected"]:
        return {"success": True, "ssid": ssid, **status}
    return {"success": False, "error": "Connection timeout"}


async def _wpa_disconnect(iface: str) -> dict:
    proc = await asyncio.create_subprocess_exec(
        "wpa_cli", "-i", iface, "disconnect",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    return {"success": True}


# ── Utility ───────────────────────────────────────────────

async def _get_ip(iface: str) -> str:
    proc = await asyncio.create_subprocess_exec(
        "ip", "-4", "-o", "addr", "show", iface,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    match = re.search(r"inet\s+([\d.]+)", stdout.decode())
    return match.group(1) if match else ""
