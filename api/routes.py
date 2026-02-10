"""REST API routes for PENSTATION."""

import asyncio
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_session
from db import crud
from pydantic import BaseModel
from scanner.scheduler import full_network_scan
from scanner.wifi import (
    connect_network,
    disconnect_network,
    forget_network,
    get_saved_networks,
    get_wifi_status,
    scan_networks,
)

logger = logging.getLogger("penstation.api")


class WifiConnectRequest(BaseModel):
    ssid: str
    password: str = ""

router = APIRouter(prefix="/api")


@router.get("/stats")
async def stats(session: AsyncSession = Depends(get_session)):
    return await crud.get_stats(session)


@router.get("/hosts")
async def hosts(session: AsyncSession = Depends(get_session)):
    host_list = await crud.get_all_hosts(session)
    result = []
    for h in host_list:
        vulns = await crud.get_host_vulns(session, h.ip)
        ports = await crud.get_host_ports(session, h.ip)
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            if v.severity in sev_counts:
                sev_counts[v.severity] += 1
        result.append({
            "ip": h.ip,
            "mac": h.mac,
            "mac_vendor": h.mac_vendor,
            "hostname": h.hostname,
            "os_name": h.os_name,
            "os_version": h.os_version,
            "status": h.status,
            "risk_score": h.risk_score,
            "first_seen": h.first_seen.isoformat() if h.first_seen else None,
            "last_seen": h.last_seen.isoformat() if h.last_seen else None,
            "ports_count": len(ports),
            "vulns": sev_counts,
        })
    return result


@router.get("/host/{ip}")
async def host_detail(ip: str, session: AsyncSession = Depends(get_session)):
    h = await crud.get_host(session, ip)
    if not h:
        return {"error": "Host not found"}
    ports = await crud.get_host_ports(session, ip)
    vulns = await crud.get_host_vulns(session, ip)
    return {
        "ip": h.ip,
        "mac": h.mac,
        "mac_vendor": h.mac_vendor,
        "hostname": h.hostname,
        "os_name": h.os_name,
        "os_version": h.os_version,
        "status": h.status,
        "risk_score": h.risk_score,
        "first_seen": h.first_seen.isoformat() if h.first_seen else None,
        "last_seen": h.last_seen.isoformat() if h.last_seen else None,
        "ports": [
            {
                "port": p.port_number,
                "protocol": p.protocol,
                "service": p.service,
                "version": p.version,
                "state": p.state,
            }
            for p in ports
        ],
        "vulns": [
            {
                "id": v.id,
                "cve_id": v.cve_id,
                "template_id": v.template_id,
                "severity": v.severity,
                "name": v.name,
                "description": v.description,
                "remediation": v.remediation,
                "reference_url": v.reference_url,
                "port": v.port_number,
                "found_at": v.found_at.isoformat() if v.found_at else None,
                "status": v.status,
            }
            for v in vulns
        ],
    }


@router.get("/host/{ip}/ports")
async def host_ports(ip: str, session: AsyncSession = Depends(get_session)):
    ports = await crud.get_host_ports(session, ip)
    return [
        {
            "port": p.port_number,
            "protocol": p.protocol,
            "service": p.service,
            "version": p.version,
            "state": p.state,
        }
        for p in ports
    ]


@router.get("/host/{ip}/vulns")
async def host_vulns(ip: str, session: AsyncSession = Depends(get_session)):
    vulns = await crud.get_host_vulns(session, ip)
    return [
        {
            "id": v.id,
            "cve_id": v.cve_id,
            "template_id": v.template_id,
            "severity": v.severity,
            "name": v.name,
            "description": v.description,
            "remediation": v.remediation,
            "reference_url": v.reference_url,
            "port": v.port_number,
            "found_at": v.found_at.isoformat() if v.found_at else None,
            "status": v.status,
        }
        for v in vulns
    ]


@router.get("/vulns")
async def all_vulns(
    severity: str = Query(None),
    session: AsyncSession = Depends(get_session),
):
    vulns = await crud.get_all_vulns(session, severity=severity)
    return [
        {
            "id": v.id,
            "host_ip": v.host_ip,
            "cve_id": v.cve_id,
            "severity": v.severity,
            "name": v.name,
            "port": v.port_number,
            "found_at": v.found_at.isoformat() if v.found_at else None,
            "status": v.status,
        }
        for v in vulns
    ]


@router.get("/scans")
async def scans(session: AsyncSession = Depends(get_session)):
    jobs = await crud.get_scan_jobs(session)
    return [
        {
            "id": j.id,
            "type": j.type,
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "finished_at": j.finished_at.isoformat() if j.finished_at else None,
            "duration": j.duration_seconds,
            "hosts_scanned": j.hosts_scanned,
            "ports_found": j.ports_found,
            "vulns_found": j.vulns_found,
            "status": j.status,
        }
        for j in jobs
    ]


@router.get("/cve/{cve_id}")
async def cve_detail(cve_id: str, session: AsyncSession = Depends(get_session)):
    entry = await crud.get_cve(session, cve_id)
    if not entry:
        return {"error": "CVE not found in local database"}
    return {
        "cve_id": entry.cve_id,
        "description": entry.description,
        "cvss_score": entry.cvss_score,
        "severity": entry.severity,
        "published_at": entry.published_at.isoformat() if entry.published_at else None,
    }


@router.get("/alerts")
async def alerts(session: AsyncSession = Depends(get_session)):
    alert_list = await crud.get_alerts(session)
    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "type": a.alert_type,
            "host_ip": a.host_ip,
            "severity": a.severity,
            "message": a.message,
        }
        for a in alert_list
    ]


@router.get("/network/map")
async def network_map(session: AsyncSession = Depends(get_session)):
    host_list = await crud.get_all_hosts(session)
    nodes = []
    edges = []
    # Add router node (gateway)
    nodes.append({
        "id": "gateway",
        "label": "Gateway",
        "type": "router",
        "severity": "none",
    })
    for h in host_list:
        vulns = await crud.get_host_vulns(session, h.ip)
        max_sev = "none"
        sev_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        for v in vulns:
            if sev_priority.get(v.severity, 0) > sev_priority.get(max_sev, -1):
                max_sev = v.severity
        nodes.append({
            "id": h.ip,
            "label": h.hostname or h.ip,
            "type": "host",
            "ip": h.ip,
            "os": h.os_name,
            "vendor": h.mac_vendor,
            "risk_score": h.risk_score,
            "severity": max_sev,
            "status": h.status,
        })
        edges.append({"from": "gateway", "to": h.ip})

    return {"nodes": nodes, "edges": edges}


@router.get("/heatmap")
async def heatmap(session: AsyncSession = Depends(get_session)):
    return await crud.get_heatmap(session)


@router.post("/scan/trigger")
async def trigger_scan():
    asyncio.create_task(full_network_scan())
    return {"status": "Scan triggered"}


# ── WiFi Management ───────────────────────────────────────

@router.get("/wifi/status")
async def wifi_status():
    return await get_wifi_status()


@router.get("/wifi/scan")
async def wifi_scan():
    return await scan_networks()


@router.post("/wifi/connect")
async def wifi_connect(req: WifiConnectRequest):
    return await connect_network(req.ssid, req.password)


@router.post("/wifi/disconnect")
async def wifi_disconnect():
    return await disconnect_network()


@router.get("/wifi/saved")
async def wifi_saved():
    return await get_saved_networks()


@router.post("/wifi/forget")
async def wifi_forget(req: WifiConnectRequest):
    return await forget_network(req.ssid)
