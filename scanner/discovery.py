"""Network host discovery using nmap."""

import asyncio
import json
import logging
import re
import socket

import httpx

from config import settings

logger = logging.getLogger("penstation.discovery")


async def get_local_subnet() -> str:
    """Auto-detect local subnet from default interface."""
    proc = await asyncio.create_subprocess_exec(
        "ip", "-j", "route", "show", "default",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    try:
        routes = json.loads(stdout.decode())
        if routes:
            dev = routes[0].get("dev", "")
            # Get IP for this interface
            proc2 = await asyncio.create_subprocess_exec(
                "ip", "-j", "-4", "addr", "show", dev,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout2, _ = await proc2.communicate()
            addrs = json.loads(stdout2.decode())
            if addrs and addrs[0].get("addr_info"):
                info = addrs[0]["addr_info"][0]
                ip = info["local"]
                prefix = info["prefixlen"]
                # Calculate network address
                parts = list(map(int, ip.split(".")))
                mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                net = [parts[i] & ((mask >> (24 - 8 * i)) & 0xFF) for i in range(4)]
                return f"{'.'.join(map(str, net))}/{prefix}"
    except Exception as e:
        logger.error("Failed to auto-detect subnet: %s", e)

    return "192.168.1.0/24"


async def resolve_hostname(ip: str) -> str:
    """Reverse DNS lookup."""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return result[0]
    except (socket.herror, socket.gaierror):
        return ""


async def get_mac_vendor(mac: str) -> str:
    """Lookup MAC vendor via macvendors.com API."""
    if not mac or mac == "00:00:00:00:00:00":
        return ""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"https://api.macvendors.com/{mac}")
            if resp.status_code == 200:
                return resp.text.strip()
    except Exception:
        pass
    return ""


async def discover_hosts(subnet: str) -> list[dict]:
    """
    Run nmap ping scan to discover live hosts.
    Returns list of dicts: {ip, mac, hostname, mac_vendor}
    """
    if subnet == "auto":
        subnet = await get_local_subnet()

    logger.info("Starting host discovery on %s", subnet)

    proc = await asyncio.create_subprocess_exec(
        "nmap", "-sn", "-PR", "-PA21,22,80,443,3389",
        "--unprivileged" if not _is_root() else "",
        subnet, "-oX", "-",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0 and not stdout:
        logger.error("nmap discovery failed: %s", stderr.decode())
        return []

    return await _parse_nmap_xml(stdout.decode())


def _is_root() -> bool:
    import os
    return os.geteuid() == 0


async def _parse_nmap_xml(xml_data: str) -> list[dict]:
    """Parse nmap XML output into host dicts."""
    hosts = []
    # Simple XML parsing with regex for lightweight approach
    host_blocks = re.findall(r"<host\b.*?</host>", xml_data, re.DOTALL)

    for block in host_blocks:
        # Check if host is up
        if 'state="up"' not in block:
            continue

        ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', block)
        if not ip_match:
            continue
        ip = ip_match.group(1)

        mac_match = re.search(r'<address addr="([^"]+)" addrtype="mac"', block)
        mac = mac_match.group(1) if mac_match else ""

        vendor_match = re.search(r'addrtype="mac"[^>]*vendor="([^"]*)"', block)
        nmap_vendor = vendor_match.group(1) if vendor_match else ""

        hostname = await resolve_hostname(ip)
        mac_vendor = nmap_vendor or await get_mac_vendor(mac)

        hosts.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "mac_vendor": mac_vendor,
        })

    logger.info("Discovered %d hosts", len(hosts))
    return hosts
