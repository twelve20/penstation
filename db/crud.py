"""CRUD operations for PENSTATION."""

from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Alert, CVEEntry, Host, Port, ScanJob, Vulnerability


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
