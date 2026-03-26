#!/usr/bin/env python3
"""Default credential checker for common services."""

import socket
import subprocess
import re
import telnetlib
import urllib.request
import urllib.error
import base64
import ssl
import time


# ──────────────────────────────────────────────────────────────
# Default credential database
# ──────────────────────────────────────────────────────────────

DEFAULT_CREDS = {
    "telnet": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", ""),
        ("root", "root"),
        ("root", ""),
        ("root", "toor"),
        ("root", "admin"),
        ("root", "password"),
        ("user", "user"),
        ("guest", "guest"),
        ("support", "support"),
    ],
    "ssh": [
        ("root", "root"),
        ("root", "toor"),
        ("root", "admin"),
        ("root", "password"),
        ("root", ""),
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("pi", "raspberry"),
        ("kali", "kali"),
        ("user", "user"),
        ("ubuntu", "ubuntu"),
    ],
    "ftp": [
        ("anonymous", ""),
        ("anonymous", "anonymous"),
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("root", "root"),
        ("ftp", "ftp"),
        ("user", "user"),
    ],
    "http": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", ""),
        ("root", "root"),
        ("root", "admin"),
        ("user", "user"),
    ],
}


# ──────────────────────────────────────────────────────────────
# Telnet checker
# ──────────────────────────────────────────────────────────────

def check_telnet(ip, port=23):
    """Check telnet for default creds or no-auth access."""
    results = []

    # first check if no password required
    try:
        tn = telnetlib.Telnet(ip, port, timeout=8)
        banner = tn.read_until(b">", timeout=5).decode("utf-8", errors="ignore")
        tn.close()

        if "(config)>" in banner or ">" in banner.split("\n")[-1]:
            if "password is not configured" in banner.lower() or "password not set" in banner.lower():
                results.append({
                    "service": "telnet",
                    "port": port,
                    "username": "N/A",
                    "password": "N/A",
                    "status": "NO PASSWORD SET",
                    "detail": "Device has no admin password configured",
                })
                return results
            results.append({
                "service": "telnet",
                "port": port,
                "username": "N/A",
                "password": "N/A",
                "status": "OPEN ACCESS",
                "detail": "Telnet shell accessible without authentication",
            })
            return results
    except Exception:
        pass

    # try default creds
    for user, passwd in DEFAULT_CREDS["telnet"]:
        try:
            tn = telnetlib.Telnet(ip, port, timeout=5)
            tn.read_until(b"ogin:", timeout=4)
            tn.write(user.encode() + b"\n")
            tn.read_until(b"assword:", timeout=4)
            tn.write(passwd.encode() + b"\n")
            response = tn.read_until(b">", timeout=4).decode("utf-8", errors="ignore")
            tn.close()

            if ">" in response and "incorrect" not in response.lower() and "failed" not in response.lower():
                results.append({
                    "service": "telnet",
                    "port": port,
                    "username": user,
                    "password": passwd if passwd else "(empty)",
                    "status": "DEFAULT CREDS",
                    "detail": f"Login successful with {user}:{passwd if passwd else '(empty)'}",
                })
                return results  # stop on first success
        except Exception:
            continue

    return results


# ──────────────────────────────────────────────────────────────
# SSH checker (uses nmap ssh-brute for reliability)
# ──────────────────────────────────────────────────────────────

def check_ssh(ip, port=22):
    """Check SSH for default credentials using hydra or manual."""
    results = []

    # try hydra if available (much faster)
    cred_lines = "\n".join(f"{u}:{p}" for u, p in DEFAULT_CREDS["ssh"])
    cred_file = f"/tmp/penstation_ssh_creds_{ip}.txt"
    try:
        with open(cred_file, "w") as f:
            f.write(cred_lines)

        result = subprocess.run(
            ["hydra", "-C", cred_file, "-t", "4", "-f",
             f"ssh://{ip}:{port}"],
            capture_output=True, text=True, timeout=120
        )

        for line in result.stdout.splitlines():
            match = re.search(r"login:\s*(\S+)\s+password:\s*(.*)", line)
            if match:
                user = match.group(1)
                passwd = match.group(2).strip()
                results.append({
                    "service": "ssh",
                    "port": port,
                    "username": user,
                    "password": passwd if passwd else "(empty)",
                    "status": "DEFAULT CREDS",
                    "detail": f"SSH login: {user}:{passwd if passwd else '(empty)'}",
                })
                return results
    except FileNotFoundError:
        # hydra not installed, try nmap
        try:
            result = subprocess.run(
                ["nmap", "-Pn", "-p", str(port),
                 "--script", "ssh-brute",
                 "--script-args",
                 f"userdb=/tmp/penstation_users.txt,passdb=/tmp/penstation_pass.txt,brute.firstonly=true",
                 ip],
                capture_output=True, text=True, timeout=120
            )
            if "Valid credentials" in result.stdout:
                match = re.search(r"Valid credentials.*?-\s*(\S+):(\S*)", result.stdout)
                if match:
                    results.append({
                        "service": "ssh",
                        "port": port,
                        "username": match.group(1),
                        "password": match.group(2) or "(empty)",
                        "status": "DEFAULT CREDS",
                        "detail": f"SSH login found via nmap",
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    except subprocess.TimeoutExpired:
        pass

    return results


# ──────────────────────────────────────────────────────────────
# FTP checker
# ──────────────────────────────────────────────────────────────

def check_ftp(ip, port=21):
    """Check FTP for anonymous access and default creds."""
    results = []

    for user, passwd in DEFAULT_CREDS["ftp"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((ip, port))
            banner = s.recv(1024).decode("utf-8", errors="ignore")

            s.send(f"USER {user}\r\n".encode())
            resp = s.recv(1024).decode("utf-8", errors="ignore")

            s.send(f"PASS {passwd}\r\n".encode())
            resp = s.recv(1024).decode("utf-8", errors="ignore")

            s.send(b"QUIT\r\n")
            s.close()

            if resp.startswith("230"):
                label = "ANONYMOUS" if user == "anonymous" else "DEFAULT CREDS"
                results.append({
                    "service": "ftp",
                    "port": port,
                    "username": user,
                    "password": passwd if passwd else "(empty)",
                    "status": label,
                    "detail": f"FTP login: {user}:{passwd if passwd else '(empty)'}",
                })
                if user == "anonymous":
                    continue  # check more creds after anonymous
                return results
        except Exception:
            continue

    return results


# ──────────────────────────────────────────────────────────────
# HTTP Basic Auth checker
# ──────────────────────────────────────────────────────────────

def check_http(ip, port=80, https=False):
    """Check HTTP for default credentials on common admin paths."""
    results = []
    scheme = "https" if https else "http"
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    admin_paths = ["/", "/admin", "/login", "/admin/login", "/management",
                   "/cgi-bin/", "/webadmin"]

    for path in admin_paths:
        url = f"{scheme}://{ip}:{port}{path}"
        try:
            req = urllib.request.Request(url, method="GET")
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            # if 200 without auth, check if it's an admin page
            body = resp.read(2048).decode("utf-8", errors="ignore").lower()
            if any(kw in body for kw in ["password", "login", "sign in", "username"]):
                # there's a login form, try default creds via basic auth
                for user, passwd in DEFAULT_CREDS["http"]:
                    try:
                        cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                        req2 = urllib.request.Request(url)
                        req2.add_header("Authorization", f"Basic {cred}")
                        resp2 = urllib.request.urlopen(req2, timeout=5, context=ctx)
                        code = resp2.getcode()
                        if code == 200:
                            body2 = resp2.read(2048).decode("utf-8", errors="ignore").lower()
                            # if still shows login form, creds didn't work
                            if "login" not in body2 and "sign in" not in body2:
                                results.append({
                                    "service": f"http{'s' if https else ''}",
                                    "port": port,
                                    "username": user,
                                    "password": passwd if passwd else "(empty)",
                                    "status": "DEFAULT CREDS",
                                    "detail": f"HTTP admin at {path}: {user}:{passwd}",
                                })
                                return results
                    except urllib.error.HTTPError:
                        continue
                    except Exception:
                        continue
        except urllib.error.HTTPError as e:
            if e.code == 401:
                # basic auth required, try creds
                for user, passwd in DEFAULT_CREDS["http"]:
                    try:
                        cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                        req2 = urllib.request.Request(url)
                        req2.add_header("Authorization", f"Basic {cred}")
                        resp2 = urllib.request.urlopen(req2, timeout=5, context=ctx)
                        if resp2.getcode() == 200:
                            results.append({
                                "service": f"http{'s' if https else ''}",
                                "port": port,
                                "username": user,
                                "password": passwd if passwd else "(empty)",
                                "status": "DEFAULT CREDS",
                                "detail": f"HTTP Basic Auth at {path}: {user}:{passwd}",
                            })
                            return results
                    except urllib.error.HTTPError:
                        continue
                    except Exception:
                        continue
        except Exception:
            continue

    return results


# ──────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────

SERVICE_CHECKERS = {
    "telnet": check_telnet,
    "ssh": check_ssh,
    "ftp": check_ftp,
    "http": check_http,
    "https": lambda ip, port: check_http(ip, port, https=True),
}


def check_default_creds(ip, open_ports):
    """
    Check all open ports for default/missing credentials.
    open_ports: list of {"port": int, "service": str, ...}
    Returns list of findings.
    """
    findings = []

    for p in open_ports:
        service = p["service"]
        port = p["port"]

        # map service names to checkers
        checker = None
        if service in SERVICE_CHECKERS:
            checker = SERVICE_CHECKERS[service]
        elif service == "http-proxy":
            checker = SERVICE_CHECKERS["http"]
        elif port == 22:
            checker = SERVICE_CHECKERS["ssh"]
        elif port == 23:
            checker = SERVICE_CHECKERS["telnet"]
        elif port == 21:
            checker = SERVICE_CHECKERS["ftp"]
        elif port in (80, 8080, 8000, 8888):
            checker = SERVICE_CHECKERS["http"]
        elif port in (443, 8443):
            checker = SERVICE_CHECKERS["https"]

        if checker:
            try:
                results = checker(ip, port)
                findings.extend(results)
            except Exception:
                continue

    return findings


def print_cred_results(ip, findings):
    """Print credential check results."""
    if not findings:
        print(f"    [{ip}] no default credentials found")
        return

    print(f"\n{'='*74}")
    print(f" DEFAULT CREDENTIALS on {ip}")
    print(f"{'='*74}")

    for f in findings:
        severity = "CRITICAL" if f["status"] in ("NO PASSWORD SET", "OPEN ACCESS") else "WARNING"
        print(f"\n [{severity}] {f['service']}:{f['port']}")
        print(f"   Status:   {f['status']}")
        print(f"   Login:    {f['username']}:{f['password']}")
        print(f"   Detail:   {f['detail']}")

    print(f"\n{'='*74}\n")
