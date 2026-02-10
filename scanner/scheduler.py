"""APScheduler jobs for automated scanning."""

import asyncio
import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from config import settings
from db.database import async_session
from db import crud
from scanner.discovery import discover_hosts
from scanner.portscan import scan_ports
from scanner.vulnscan import nuclei_scan
from scanner.cve_updater import update_cve_database, enrich_cve

logger = logging.getLogger("penstation.scheduler")

# Global reference for WebSocket log broadcasting
_log_callback = None
_alert_callback = None

scheduler = AsyncIOScheduler()


def set_log_callback(cb):
    global _log_callback
    _log_callback = cb


def set_alert_callback(cb):
    global _alert_callback
    _alert_callback = cb


async def _broadcast_log(level: str, message: str):
    if _log_callback:
        await _log_callback(level, message)


async def _broadcast_alert(alert_data: dict):
    if _alert_callback:
        await _alert_callback(alert_data)


async def full_network_scan():
    """Complete scan cycle: discover → portscan → vulnscan."""
    logger.info("=== Starting full network scan ===")
    await _broadcast_log("INFO", "Starting full network scan...")

    async with async_session() as session:
        job = await crud.create_scan_job(session, "full_scan")

    try:
        # Phase 1: Discovery
        await _broadcast_log("INFO", "Phase 1: Host discovery...")
        subnet = settings.SUBNET
        hosts = await discover_hosts(subnet)
        active_ips = [h["ip"] for h in hosts]

        async with async_session() as session:
            await crud.mark_inactive_hosts(session, active_ips)

            for h in hosts:
                host = await crud.upsert_host(
                    session,
                    ip=h["ip"],
                    mac=h.get("mac", ""),
                    mac_vendor=h.get("mac_vendor", ""),
                    hostname=h.get("hostname", ""),
                    status="active",
                )
                if host.first_seen == host.last_seen:
                    # New host
                    await _broadcast_log("WARN", f"New host discovered: {h['ip']} ({h.get('hostname', 'unknown')})")
                    if settings.ALERT_ON_NEW_HOST:
                        alert = await crud.add_alert(
                            session,
                            alert_type="new_host",
                            host_ip=h["ip"],
                            severity="info",
                            message=f"New host: {h['ip']} ({h.get('mac_vendor', '')})",
                        )
                        await _broadcast_alert({
                            "type": "new_host",
                            "ip": h["ip"],
                            "severity": "info",
                            "message": alert.message,
                        })

        await _broadcast_log("OK", f"Discovery complete: {len(hosts)} hosts found")

        # Phase 2: Port scanning
        await _broadcast_log("INFO", "Phase 2: Port scanning...")
        total_ports = 0

        for h in hosts:
            ip = h["ip"]
            await _broadcast_log("INFO", f"Scanning ports on {ip}...")
            try:
                result = await scan_ports(ip)
                async with async_session() as session:
                    if result.get("os_name"):
                        await crud.upsert_host(
                            session, ip=ip,
                            os_name=result["os_name"],
                            os_version=result.get("os_version", ""),
                        )
                    for p in result.get("ports", []):
                        await crud.upsert_port(
                            session,
                            host_ip=ip,
                            port_number=p["port"],
                            protocol=p.get("protocol", "tcp"),
                            service=p.get("service", ""),
                            version=p.get("version", ""),
                            state="open",
                        )
                        total_ports += 1
                await _broadcast_log("OK", f"{ip}: {len(result.get('ports', []))} open ports")
            except Exception as e:
                logger.error("Port scan failed for %s: %s", ip, e)
                await _broadcast_log("CRITICAL", f"Port scan failed for {ip}: {e}")

        await _broadcast_log("OK", f"Port scan complete: {total_ports} open ports total")

        # Phase 3: Vulnerability scanning
        await _broadcast_log("INFO", "Phase 3: Vulnerability scanning...")
        total_vulns = 0

        for h in hosts:
            ip = h["ip"]
            async with async_session() as session:
                ports = await crud.get_host_ports(session, ip)
                port_numbers = [p.port_number for p in ports]

            if not port_numbers:
                continue

            await _broadcast_log("INFO", f"Nuclei scanning {ip}...")
            try:
                vulns = await nuclei_scan(ip, port_numbers)
                async with async_session() as session:
                    for v in vulns:
                        await crud.add_vulnerability(
                            session,
                            host_ip=ip,
                            port_number=v.get("port", 0),
                            cve_id=v.get("cve_id", ""),
                            template_id=v.get("template_id", ""),
                            severity=v.get("severity", "info"),
                            name=v.get("name", ""),
                            description=v.get("description", ""),
                            remediation=v.get("remediation", ""),
                            reference_url=v.get("reference_url", ""),
                        )
                        total_vulns += 1

                        # Enrich CVE data
                        if v.get("cve_id"):
                            asyncio.create_task(enrich_cve(v["cve_id"]))

                        # Alert on critical
                        if v.get("severity") == "critical" and settings.ALERT_ON_CRITICAL:
                            alert_msg = f"CRITICAL: {v.get('name', '')} on {ip}:{v.get('port', '')} ({v.get('cve_id', '')})"
                            await _broadcast_log("CRITICAL", alert_msg)
                            alert = await crud.add_alert(
                                session,
                                alert_type="vuln",
                                host_ip=ip,
                                severity="critical",
                                message=alert_msg,
                            )
                            await _broadcast_alert({
                                "type": "critical_vuln",
                                "ip": ip,
                                "severity": "critical",
                                "message": alert_msg,
                                "cve_id": v.get("cve_id", ""),
                            })

                    # Update risk score
                    await crud.calculate_risk_score(session, ip)

                if vulns:
                    await _broadcast_log("WARN", f"{ip}: {len(vulns)} vulnerabilities found")
                else:
                    await _broadcast_log("OK", f"{ip}: clean")

            except Exception as e:
                logger.error("Vuln scan failed for %s: %s", ip, e)
                await _broadcast_log("CRITICAL", f"Vuln scan failed for {ip}: {e}")

        # Finish
        async with async_session() as session:
            await crud.finish_scan_job(
                session, job.id,
                hosts_scanned=len(hosts),
                ports_found=total_ports,
                vulns_found=total_vulns,
                status="completed",
            )

        summary = f"Scan complete: {len(hosts)} hosts, {total_ports} ports, {total_vulns} vulns"
        await _broadcast_log("OK", summary)
        logger.info(summary)

    except Exception as e:
        logger.error("Full scan failed: %s", e)
        await _broadcast_log("CRITICAL", f"Scan failed: {e}")
        async with async_session() as session:
            await crud.finish_scan_job(session, job.id, status="failed", error_message=str(e))


async def update_templates_job():
    """Nightly template and CVE database update."""
    logger.info("Starting template update job")
    await _broadcast_log("INFO", "Updating vulnerability templates...")

    async with async_session() as session:
        job = await crud.create_scan_job(session, "update")

    try:
        await update_cve_database()
        async with async_session() as session:
            await crud.finish_scan_job(session, job.id, status="completed")
        await _broadcast_log("OK", "Templates and CVE database updated")
    except Exception as e:
        logger.error("Update job failed: %s", e)
        async with async_session() as session:
            await crud.finish_scan_job(session, job.id, status="failed", error_message=str(e))


async def cleanup_job():
    """Remove old vulnerability data for offline hosts."""
    logger.info("Running cleanup job")
    async with async_session() as session:
        await crud.cleanup_old_vulns(session, days=30)
    logger.info("Cleanup complete")


def start_scheduler():
    """Configure and start all scheduled jobs."""
    scheduler.add_job(
        full_network_scan,
        "interval",
        hours=settings.SCAN_INTERVAL_HOURS,
        id="full_scan",
        replace_existing=True,
        next_run_time=datetime.utcnow(),  # run immediately on start
    )
    scheduler.add_job(
        update_templates_job,
        "cron",
        hour=settings.TEMPLATE_UPDATE_HOUR,
        minute=0,
        id="update_templates",
        replace_existing=True,
    )
    scheduler.add_job(
        cleanup_job,
        "cron",
        hour=4,
        minute=0,
        id="cleanup",
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Scheduler started")


def stop_scheduler():
    """Gracefully stop the scheduler."""
    if scheduler.running:
        scheduler.shutdown(wait=True)
        logger.info("Scheduler stopped")
