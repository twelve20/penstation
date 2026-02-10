"""Port scanning and service/OS detection using nmap."""

import asyncio
import logging
import re

from config import settings

logger = logging.getLogger("penstation.portscan")


async def scan_ports(ip: str) -> dict:
    """
    Scan top 1000 ports with service/version and OS detection.
    Returns: {ip, os_name, os_version, ports: [{port, protocol, service, version, state}]}
    """
    logger.info("Port scanning %s", ip)

    cmd = [
        "nmap", "-sV", "-sS", "-O",
        "--top-ports", "1000",
        f"-{settings.NMAP_TIMING}",
        "--open",
        "-oX", "-",
        ip,
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode not in (0, 1) and not stdout:
        # nmap returns 1 when some hosts are down — still has output
        logger.error("nmap port scan failed for %s: %s", ip, stderr.decode())
        return {"ip": ip, "os_name": "", "os_version": "", "ports": []}

    return _parse_portscan_xml(ip, stdout.decode())


def _parse_portscan_xml(ip: str, xml_data: str) -> dict:
    """Parse nmap port scan XML output."""
    result = {"ip": ip, "os_name": "", "os_version": "", "ports": []}

    # OS detection
    os_match = re.search(r'<osmatch name="([^"]*)"[^>]*accuracy="([^"]*)"', xml_data)
    if os_match:
        result["os_name"] = os_match.group(1)

    osclass_match = re.search(
        r'<osclass[^>]*osfamily="([^"]*)"[^>]*osgen="([^"]*)"', xml_data
    )
    if osclass_match:
        if not result["os_name"]:
            result["os_name"] = osclass_match.group(1)
        result["os_version"] = osclass_match.group(2)

    # Ports
    port_blocks = re.findall(r"<port\b.*?</port>", xml_data, re.DOTALL)
    for block in port_blocks:
        state_match = re.search(r'<state state="([^"]*)"', block)
        if not state_match or state_match.group(1) != "open":
            continue

        port_match = re.search(r'protocol="([^"]*)" portid="(\d+)"', block)
        if not port_match:
            continue

        service_match = re.search(
            r'<service name="([^"]*)"(?:[^>]*product="([^"]*)")?(?:[^>]*version="([^"]*)")?',
            block,
        )

        port_info = {
            "port": int(port_match.group(2)),
            "protocol": port_match.group(1),
            "service": service_match.group(1) if service_match else "",
            "version": "",
            "state": "open",
        }

        if service_match:
            parts = []
            if service_match.group(2):
                parts.append(service_match.group(2))
            if service_match.group(3):
                parts.append(service_match.group(3))
            port_info["version"] = " ".join(parts)

        result["ports"].append(port_info)

    logger.info("Found %d open ports on %s", len(result["ports"]), ip)
    return result
