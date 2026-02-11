"""CRUD operations for PENSTATION."""

from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import (
    Alert,
    BluetoothDevice,
    BruteForceResult,
    CVEEntry,
    Host,
    Plugin,
    Port,
    ScanJob,
    StolenFile,
    Vulnerability,
    WiFiAttack,
    WiFiClient,
    WiFiHandshake,
    WiFiNetwork,
)


# ── Hosts ──────────────────────────────────────────────────────────

async def upsert_host(session: AsyncSession, ip: str, **kwargs) -> Host:
    result = await session.execute(select(Host).where(Host.ip == ip))
    host = result.scalar_one_or_none()
    if host:
        for k, v in kwargs.items():
            if v is not None:
                setattr(host, k, v)
        host.last_seen = datetime.utcnow()
    else:
        host = Host(ip=ip, **kwargs)
        session.add(host)
    await session.commit()
    return host


async def get_host(session: AsyncSession, ip: str) -> Optional[Host]:
    result = await session.execute(select(Host).where(Host.ip == ip))
    return result.scalar_one_or_none()


async def get_all_hosts(session: AsyncSession) -> list[Host]:
    result = await session.execute(select(Host).order_by(Host.risk_score.desc()))
    return list(result.scalars().all())


async def mark_inactive_hosts(session: AsyncSession, active_ips: list[str]):
    await session.execute(
        update(Host)
        .where(Host.ip.notin_(active_ips), Host.status != "inactive")
        .values(status="inactive")
    )
    await session.execute(
        update(Host)
        .where(Host.ip.in_(active_ips))
        .values(status="active", last_seen=datetime.utcnow())
    )
    await session.commit()


# ── Ports ──────────────────────────────────────────────────────────

async def upsert_port(session: AsyncSession, host_ip: str, port_number: int, **kwargs) -> Port:
    result = await session.execute(
        select(Port).where(Port.host_ip == host_ip, Port.port_number == port_number)
    )
    port = result.scalar_one_or_none()
    if port:
        for k, v in kwargs.items():
            if v is not None:
                setattr(port, k, v)
        port.last_seen = datetime.utcnow()
    else:
        port = Port(host_ip=host_ip, port_number=port_number, **kwargs)
        session.add(port)
    await session.commit()
    return port


async def get_host_ports(session: AsyncSession, host_ip: str) -> list[Port]:
    result = await session.execute(
        select(Port).where(Port.host_ip == host_ip).order_by(Port.port_number)
    )
    return list(result.scalars().all())


# ── Vulnerabilities ────────────────────────────────────────────────

async def add_vulnerability(session: AsyncSession, **kwargs) -> Vulnerability:
    vuln = Vulnerability(**kwargs)
    session.add(vuln)
    await session.commit()
    return vuln


async def get_host_vulns(session: AsyncSession, host_ip: str) -> list[Vulnerability]:
    result = await session.execute(
        select(Vulnerability).where(Vulnerability.host_ip == host_ip).order_by(Vulnerability.severity)
    )
    return list(result.scalars().all())


async def get_all_vulns(
    session: AsyncSession,
    severity: Optional[str] = None,
) -> list[Vulnerability]:
    q = select(Vulnerability)
    if severity:
        q = q.where(Vulnerability.severity == severity)
    q = q.order_by(Vulnerability.found_at.desc())
    result = await session.execute(q)
    return list(result.scalars().all())


async def cleanup_old_vulns(session: AsyncSession, days: int = 30):
    cutoff = datetime.utcnow() - timedelta(days=days)
    inactive_ips_q = select(Host.ip).where(Host.status == "inactive")
    inactive_result = await session.execute(inactive_ips_q)
    inactive_ips = [r[0] for r in inactive_result.all()]
    if inactive_ips:
        await session.execute(
            delete(Vulnerability).where(
                Vulnerability.host_ip.in_(inactive_ips),
                Vulnerability.last_seen < cutoff,
            )
        )
        await session.commit()


# ── Risk Score ─────────────────────────────────────────────────────

async def calculate_risk_score(session: AsyncSession, host_ip: str) -> int:
    vulns = await get_host_vulns(session, host_ip)
    ports = await get_host_ports(session, host_ip)
    score = 0
    for v in vulns:
        if v.severity == "critical":
            score += 25
        elif v.severity == "high":
            score += 10
        elif v.severity == "medium":
            score += 5
        elif v.severity == "low":
            score += 1
    score += len(ports) * 2
    score = min(score, 100)
    await session.execute(update(Host).where(Host.ip == host_ip).values(risk_score=score))
    await session.commit()
    return score


# ── Scan Jobs ──────────────────────────────────────────────────────

async def create_scan_job(session: AsyncSession, scan_type: str) -> ScanJob:
    job = ScanJob(type=scan_type, started_at=datetime.utcnow())
    session.add(job)
    await session.commit()
    return job


async def finish_scan_job(session: AsyncSession, job_id: int, **kwargs):
    now = datetime.utcnow()
    result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = result.scalar_one_or_none()
    if job:
        job.finished_at = now
        job.duration_seconds = (now - job.started_at).total_seconds()
        job.status = kwargs.get("status", "completed")
        for k, v in kwargs.items():
            if hasattr(job, k):
                setattr(job, k, v)
        await session.commit()
    return job


async def get_scan_jobs(session: AsyncSession, limit: int = 50) -> list[ScanJob]:
    result = await session.execute(
        select(ScanJob).order_by(ScanJob.started_at.desc()).limit(limit)
    )
    return list(result.scalars().all())


# ── CVE Entries ────────────────────────────────────────────────────

async def upsert_cve(session: AsyncSession, cve_id: str, **kwargs) -> CVEEntry:
    result = await session.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
    entry = result.scalar_one_or_none()
    if entry:
        for k, v in kwargs.items():
            if v is not None:
                setattr(entry, k, v)
    else:
        entry = CVEEntry(cve_id=cve_id, **kwargs)
        session.add(entry)
    await session.commit()
    return entry


async def get_cve(session: AsyncSession, cve_id: str) -> Optional[CVEEntry]:
    result = await session.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
    return result.scalar_one_or_none()


# ── Alerts ─────────────────────────────────────────────────────────

async def add_alert(session: AsyncSession, **kwargs) -> Alert:
    alert = Alert(**kwargs)
    session.add(alert)
    await session.commit()
    return alert


async def get_alerts(session: AsyncSession, limit: int = 100) -> list[Alert]:
    result = await session.execute(
        select(Alert).order_by(Alert.timestamp.desc()).limit(limit)
    )
    return list(result.scalars().all())


# ── Stats ──────────────────────────────────────────────────────────

async def get_stats(session: AsyncSession) -> dict:
    hosts_total = (await session.execute(select(func.count(Host.id)))).scalar() or 0
    hosts_active = (
        await session.execute(select(func.count(Host.id)).where(Host.status == "active"))
    ).scalar() or 0

    sev_counts = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        c = (
            await session.execute(
                select(func.count(Vulnerability.id)).where(
                    Vulnerability.severity == sev, Vulnerability.status == "active"
                )
            )
        ).scalar() or 0
        sev_counts[sev] = c

    last_scan_row = await session.execute(
        select(ScanJob).order_by(ScanJob.started_at.desc()).limit(1)
    )
    last_scan = last_scan_row.scalar_one_or_none()

    return {
        "hosts_total": hosts_total,
        "hosts_active": hosts_active,
        "vulns": sev_counts,
        "last_scan": {
            "type": last_scan.type if last_scan else None,
            "started_at": last_scan.started_at.isoformat() if last_scan else None,
            "status": last_scan.status if last_scan else None,
        },
    }


async def get_heatmap(session: AsyncSession, days: int = 30) -> list[dict]:
    """Return max severity per day for the heatmap."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    result = await session.execute(
        select(Vulnerability.found_at, Vulnerability.severity)
        .where(Vulnerability.found_at >= cutoff)
        .order_by(Vulnerability.found_at)
    )
    day_map: dict[str, int] = {}
    severity_weight = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for row in result.all():
        day_key = row[0].strftime("%Y-%m-%d")
        w = severity_weight.get(row[1], 0)
        if day_key not in day_map or w > day_map[day_key]:
            day_map[day_key] = w
    weight_to_sev = {v: k for k, v in severity_weight.items()}
    return [
        {"date": d, "severity": weight_to_sev.get(w, "info")}
        for d, w in sorted(day_map.items())
    ]


# ── WiFi Networks ──────────────────────────────────────────────────

async def upsert_wifi_network(session: AsyncSession, bssid: str, **kwargs) -> WiFiNetwork:
    """Create or update WiFi network by BSSID."""
    result = await session.execute(select(WiFiNetwork).where(WiFiNetwork.bssid == bssid))
    network = result.scalar_one_or_none()
    if network:
        for k, v in kwargs.items():
            if v is not None:
                setattr(network, k, v)
        network.last_seen = datetime.utcnow()
    else:
        network = WiFiNetwork(bssid=bssid, **kwargs)
        session.add(network)
    await session.commit()
    return network


async def get_all_wifi_networks(session: AsyncSession) -> list[WiFiNetwork]:
    """Get all WiFi networks ordered by signal strength."""
    result = await session.execute(
        select(WiFiNetwork).order_by(WiFiNetwork.signal.desc())
    )
    return list(result.scalars().all())


async def get_wifi_network(session: AsyncSession, bssid: str) -> Optional[WiFiNetwork]:
    """Get WiFi network by BSSID."""
    result = await session.execute(select(WiFiNetwork).where(WiFiNetwork.bssid == bssid))
    return result.scalar_one_or_none()


# ── WiFi Clients ───────────────────────────────────────────────────

async def upsert_wifi_client(session: AsyncSession, mac: str, **kwargs) -> WiFiClient:
    """Create or update WiFi client by MAC."""
    result = await session.execute(select(WiFiClient).where(WiFiClient.mac == mac))
    client = result.scalar_one_or_none()
    if client:
        for k, v in kwargs.items():
            if v is not None:
                setattr(client, k, v)
        client.last_seen = datetime.utcnow()
    else:
        client = WiFiClient(mac=mac, **kwargs)
        session.add(client)
    await session.commit()
    return client


async def get_all_wifi_clients(session: AsyncSession) -> list[WiFiClient]:
    """Get all WiFi clients ordered by last seen."""
    result = await session.execute(
        select(WiFiClient).order_by(WiFiClient.last_seen.desc())
    )
    return list(result.scalars().all())


async def get_wifi_clients_for_network(session: AsyncSession, bssid: str) -> list[WiFiClient]:
    """Get all clients connected to a specific network."""
    result = await session.execute(
        select(WiFiClient).where(WiFiClient.connected_to_bssid == bssid)
    )
    return list(result.scalars().all())


# ── WiFi Handshakes ────────────────────────────────────────────────

async def add_wifi_handshake(session: AsyncSession, **kwargs) -> WiFiHandshake:
    """Add captured WiFi handshake."""
    handshake = WiFiHandshake(**kwargs)
    session.add(handshake)
    await session.commit()
    return handshake


async def get_all_handshakes(session: AsyncSession) -> list[WiFiHandshake]:
    """Get all captured handshakes."""
    result = await session.execute(
        select(WiFiHandshake).order_by(WiFiHandshake.captured_at.desc())
    )
    return list(result.scalars().all())


async def get_handshake(session: AsyncSession, handshake_id: int) -> Optional[WiFiHandshake]:
    """Get handshake by ID."""
    result = await session.execute(select(WiFiHandshake).where(WiFiHandshake.id == handshake_id))
    return result.scalar_one_or_none()


async def mark_handshake_cracked(session: AsyncSession, handshake_id: int, password: str):
    """Mark handshake as cracked with password."""
    await session.execute(
        update(WiFiHandshake)
        .where(WiFiHandshake.id == handshake_id)
        .values(cracked=True, password=password)
    )
    await session.commit()


async def count_handshakes(session: AsyncSession) -> int:
    """Count total handshakes captured."""
    result = await session.execute(select(func.count(WiFiHandshake.id)))
    return result.scalar() or 0


# ── WiFi Attacks ───────────────────────────────────────────────────

async def log_attack(session: AsyncSession, **kwargs) -> WiFiAttack:
    """Log a WiFi attack."""
    attack = WiFiAttack(**kwargs)
    session.add(attack)
    await session.commit()
    return attack


async def update_attack_status(
    session: AsyncSession, attack_id: int, status: str, **kwargs
):
    """Update WiFi attack status."""
    result = await session.execute(select(WiFiAttack).where(WiFiAttack.id == attack_id))
    attack = result.scalar_one_or_none()
    if attack:
        attack.status = status
        attack.finished_at = datetime.utcnow()
        for k, v in kwargs.items():
            if hasattr(attack, k):
                setattr(attack, k, v)
        await session.commit()
    return attack


async def get_recent_attacks(session: AsyncSession, minutes: int = 5) -> list[WiFiAttack]:
    """Get attacks from last N minutes."""
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    result = await session.execute(
        select(WiFiAttack).where(WiFiAttack.started_at >= cutoff)
    )
    return list(result.scalars().all())


async def count_recent_attacks(session: AsyncSession, minutes: int = 5) -> int:
    """Count attacks in last N minutes (for rate limiting)."""
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    result = await session.execute(
        select(func.count(WiFiAttack.id)).where(WiFiAttack.started_at >= cutoff)
    )
    return result.scalar() or 0


# ── Brute Force Results ────────────────────────────────────────────

async def store_credential(session: AsyncSession, **kwargs) -> BruteForceResult:
    """Store brute force result (successful or failed)."""
    result_obj = BruteForceResult(**kwargs)
    session.add(result_obj)
    await session.commit()
    return result_obj


async def get_credentials_for_host(
    session: AsyncSession, host_ip: str
) -> list[BruteForceResult]:
    """Get all brute force results for a host."""
    result = await session.execute(
        select(BruteForceResult)
        .where(BruteForceResult.host_ip == host_ip)
        .order_by(BruteForceResult.found_at.desc())
    )
    return list(result.scalars().all())


async def get_successful_credentials(session: AsyncSession) -> list[BruteForceResult]:
    """Get all successful credentials."""
    result = await session.execute(
        select(BruteForceResult)
        .where(BruteForceResult.success == True)
        .order_by(BruteForceResult.found_at.desc())
    )
    return list(result.scalars().all())


# ── Stolen Files ───────────────────────────────────────────────────

async def log_stolen_file(session: AsyncSession, **kwargs) -> StolenFile:
    """Log a stolen file."""
    file_obj = StolenFile(**kwargs)
    session.add(file_obj)
    await session.commit()
    return file_obj


async def get_stolen_files_for_host(session: AsyncSession, host_ip: str) -> list[StolenFile]:
    """Get all stolen files from a host."""
    result = await session.execute(
        select(StolenFile)
        .where(StolenFile.host_ip == host_ip)
        .order_by(StolenFile.stolen_at.desc())
    )
    return list(result.scalars().all())


async def get_all_stolen_files(session: AsyncSession) -> list[StolenFile]:
    """Get all stolen files."""
    result = await session.execute(
        select(StolenFile).order_by(StolenFile.stolen_at.desc())
    )
    return list(result.scalars().all())


# ── Bluetooth Devices ──────────────────────────────────────────────

async def store_bluetooth_device(session: AsyncSession, mac: str, **kwargs) -> BluetoothDevice:
    """Store or update Bluetooth device."""
    result = await session.execute(select(BluetoothDevice).where(BluetoothDevice.mac == mac))
    device = result.scalar_one_or_none()
    if device:
        for k, v in kwargs.items():
            if v is not None:
                setattr(device, k, v)
        device.last_seen = datetime.utcnow()
    else:
        device = BluetoothDevice(mac=mac, **kwargs)
        session.add(device)
    await session.commit()
    return device


async def get_all_bluetooth_devices(session: AsyncSession) -> list[BluetoothDevice]:
    """Get all Bluetooth devices."""
    result = await session.execute(
        select(BluetoothDevice).order_by(BluetoothDevice.last_seen.desc())
    )
    return list(result.scalars().all())


# ── Plugins ────────────────────────────────────────────────────────

async def add_plugin(session: AsyncSession, **kwargs) -> Plugin:
    """Add a plugin."""
    plugin = Plugin(**kwargs)
    session.add(plugin)
    await session.commit()
    return plugin


async def get_all_plugins(session: AsyncSession) -> list[Plugin]:
    """Get all plugins."""
    result = await session.execute(select(Plugin).order_by(Plugin.name))
    return list(result.scalars().all())


async def get_plugin(session: AsyncSession, name: str) -> Optional[Plugin]:
    """Get plugin by name."""
    result = await session.execute(select(Plugin).where(Plugin.name == name))
    return result.scalar_one_or_none()


async def update_plugin_config(session: AsyncSession, name: str, config: str):
    """Update plugin configuration."""
    await session.execute(
        update(Plugin).where(Plugin.name == name).values(config=config)
    )
    await session.commit()


async def toggle_plugin(session: AsyncSession, name: str, enabled: bool):
    """Enable or disable a plugin."""
    await session.execute(
        update(Plugin).where(Plugin.name == name).values(enabled=enabled)
    )
    await session.commit()
