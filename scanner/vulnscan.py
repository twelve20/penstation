"""Vulnerability scanning using Nuclei."""

import asyncio
import json
import logging

from config import settings

logger = logging.getLogger("penstation.vulnscan")

# Map port ranges to nuclei template tags
PORT_TEMPLATE_MAP = {
    (80, 443, 8080, 8443, 8000, 8888): "http",
    (22,): "ssh",
    (21,): "ftp",
    (445, 139): "smb",
    (3306,): "mysql",
    (5432,): "postgres",
    (6379,): "redis",
    (27017,): "mongodb",
    (3389,): "rdp",
    (25, 465, 587): "smtp",
    (53,): "dns",
    (161,): "snmp",
}


def _get_tags_for_ports(ports: list[int]) -> list[str]:
    """Determine nuclei template tags based on discovered ports."""
    tags = set()
    for port in ports:
        for port_tuple, tag in PORT_TEMPLATE_MAP.items():
            if port in port_tuple:
                tags.add(tag)
    if not tags:
        tags.add("network")
    return list(tags)


def _build_targets(ip: str, ports: list[int]) -> list[str]:
    """Build target URLs for nuclei."""
    targets = []
    for port in ports:
        if port in (80, 8080, 8000, 8888):
            targets.append(f"http://{ip}:{port}")
        elif port in (443, 8443):
            targets.append(f"https://{ip}:{port}")
        else:
            targets.append(f"{ip}:{port}")
    if not targets:
        targets.append(ip)
    return targets


async def nuclei_scan(ip: str, ports: list[int]) -> list[dict]:
    """
    Run nuclei vulnerability scan against a host.
    Returns list of vulnerability dicts.
    """
    logger.info("Starting nuclei scan on %s (ports: %s)", ip, ports)

    tags = _get_tags_for_ports(ports)
    targets = _build_targets(ip, ports)

    vulns = []
    for target in targets:
        try:
            result = await _run_nuclei(target, tags)
            vulns.extend(result)
        except Exception as e:
            logger.error("Nuclei scan error for %s: %s", target, e)

    logger.info("Nuclei found %d vulnerabilities on %s", len(vulns), ip)
    return vulns


async def _run_nuclei(target: str, tags: list[str]) -> list[dict]:
    """Execute nuclei process and parse JSON output."""
    cmd = [
        settings.NUCLEI_BIN,
        "-target", target,
        "-tags", ",".join(tags),
        "-severity", settings.SEVERITY_FILTER,
        "-rate-limit", str(settings.NUCLEI_RATE_LIMIT),
        "-timeout", str(settings.NUCLEI_TIMEOUT),
        "-jsonl",
        "-silent",
        "-no-color",
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode not in (0, 1):
        logger.warning("Nuclei returned code %d for %s: %s", proc.returncode, target, stderr.decode()[:500])

    vulns = []
    for line in stdout.decode().strip().split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            vuln = _parse_nuclei_result(data)
            if vuln:
                vulns.append(vuln)
        except json.JSONDecodeError:
            continue

    return vulns


def _parse_nuclei_result(data: dict) -> dict | None:
    """Parse a single nuclei JSON result into a vulnerability dict."""
    info = data.get("info", {})
    if not info:
        return None

    severity = info.get("severity", "info").lower()
    cve_ids = info.get("classification", {}).get("cve-id") or []
    cve_id = cve_ids[0] if cve_ids else ""
    references = info.get("reference") or []

    return {
        "template_id": data.get("template-id", ""),
        "cve_id": cve_id,
        "severity": severity,
        "name": info.get("name", ""),
        "description": info.get("description", ""),
        "remediation": info.get("remediation", ""),
        "reference_url": references[0] if references else "",
        "matched_at": data.get("matched-at", ""),
        "port": _extract_port(data.get("matched-at", "")),
    }


def _extract_port(matched_at: str) -> int:
    """Extract port number from matched-at URL."""
    import re
    m = re.search(r":(\d+)", matched_at)
    if m:
        port = int(m.group(1))
        if port < 65536:
            return port
    if matched_at.startswith("https://"):
        return 443
    if matched_at.startswith("http://"):
        return 80
    return 0
