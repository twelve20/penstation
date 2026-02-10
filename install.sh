#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  PENSTATION — Installer for Raspberry Pi (Raspbian/Debian)
# ═══════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

INSTALL_DIR="$HOME/penstation"
VENV_DIR="$INSTALL_DIR/venv"

log()   { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; }
info()  { echo -e "${CYAN}[i]${NC} $1"; }

banner() {
cat << 'EOF'

  ██████╗ ███████╗███╗   ██╗███████╗████████╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝████╗  ██║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██╔██╗ ██║███████╗   ██║   ███████║   ██║   ██║██║   ██║██╔██╗ ██║
  ██╔═══╝ ██╔══╝  ██║╚██╗██║╚════██║   ██║   ██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
  ██║     ███████╗██║ ╚████║███████║   ██║   ██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
  ╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

  Autonomous Network Security Station — Installer v1.0

EOF
}

# ── Check root ─────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root (sudo)"
        exit 1
    fi
}

# ── Check architecture ─────────────────────────────────────
check_arch() {
    local arch
    arch=$(uname -m)
    log "Detected architecture: $arch"
    if [[ "$arch" != "armv7l" && "$arch" != "aarch64" && "$arch" != "armv6l" ]]; then
        warn "Not running on ARM — this installer is designed for Raspberry Pi"
        read -rp "Continue anyway? [y/N] " cont
        [[ "$cont" =~ ^[Yy]$ ]] || exit 0
    fi
}

# ── WiFi Check ─────────────────────────────────────────────
setup_wifi() {
    echo ""
    echo -e "${BOLD}═══ WiFi ═══${NC}"
    echo ""

    if ! iw dev 2>/dev/null | grep -q Interface; then
        warn "No WiFi interface detected"
        info "You can connect via Ethernet and manage WiFi later through the web dashboard"
        return
    fi

    # Check if already connected
    if ping -c1 -W2 8.8.8.8 &>/dev/null; then
        log "Internet connection detected — OK"
        info "WiFi can be managed anytime through the PENSTATION web dashboard"
        return
    fi

    warn "No internet connection detected"
    info "After installation, connect WiFi through the web dashboard (WiFi button in header)"
    info "For now, make sure you have Ethernet connected"
    echo ""
    read -rp "Continue installation? [Y/n] " cont
    [[ "$cont" =~ ^[Nn]$ ]] && exit 0
}

# ── System Update ──────────────────────────────────────────
update_system() {
    log "Updating system packages..."
    apt-get update -qq
    apt-get upgrade -y -qq
}

# ── Install Dependencies ──────────────────────────────────
install_deps() {
    log "Installing system dependencies..."
    apt-get install -y -qq \
        nmap masscan \
        python3 python3-pip python3-venv \
        nginx git curl unzip wget \
        sqlite3 libsqlite3-dev \
        net-tools wireless-tools iw
}

# ── Install Nuclei ─────────────────────────────────────────
install_nuclei() {
    if command -v nuclei &>/dev/null; then
        log "Nuclei already installed: $(nuclei -version 2>&1 | head -1)"
        return
    fi

    log "Installing Nuclei vulnerability scanner..."
    local arch
    arch=$(uname -m)
    local nuclei_arch="linux_arm64"

    case "$arch" in
        aarch64)  nuclei_arch="linux_arm64" ;;
        armv7l)   nuclei_arch="linux_armv6" ;;
        armv6l)   nuclei_arch="linux_armv6" ;;
        x86_64)   nuclei_arch="linux_amd64" ;;
        *)        err "Unsupported architecture: $arch"; return ;;
    esac

    # Get latest release URL from GitHub API
    local download_url
    download_url=$(curl -sL "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" | \
        grep "browser_download_url.*${nuclei_arch}.zip" | \
        head -1 | cut -d '"' -f 4)

    if [[ -z "$download_url" ]]; then
        err "Could not find Nuclei download URL"
        return
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)
    log "Downloading Nuclei from $download_url..."
    wget -q -O "$tmp_dir/nuclei.zip" "$download_url"
    unzip -q "$tmp_dir/nuclei.zip" -d "$tmp_dir"
    install -m 755 "$tmp_dir/nuclei" /usr/local/bin/nuclei
    rm -rf "$tmp_dir"

    log "Nuclei installed: $(nuclei -version 2>&1 | head -1)"

    # Download templates
    log "Downloading Nuclei templates (this may take a while)..."
    sudo -u "${SUDO_USER:-pi}" nuclei -update-templates 2>/dev/null || true
}

# ── Setup Python Environment ──────────────────────────────
setup_python() {
    log "Setting up Python virtual environment..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"

    log "Installing Python dependencies..."
    pip install --quiet --upgrade pip
    pip install --quiet -r "$INSTALL_DIR/requirements.txt"
}

# ── Initialize Database ───────────────────────────────────
init_database() {
    log "Initializing database..."
    source "$VENV_DIR/bin/activate"
    cd "$INSTALL_DIR"
    python3 -c "
import asyncio
from db.database import init_db
asyncio.run(init_db())
print('Database initialized successfully')
"
}

# ── Configure Nginx ────────────────────────────────────────
setup_nginx() {
    log "Configuring Nginx reverse proxy..."
    cat > /etc/nginx/sites-available/penstation << 'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml;
    gzip_min_length 256;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }

    location /static/ {
        alias /home/PENSTATION_USER/penstation/static/;
        expires 1h;
        add_header Cache-Control "public, immutable";
    }
}
NGINX

    # Replace user placeholder
    local user="${SUDO_USER:-pi}"
    sed -i "s/PENSTATION_USER/$user/g" /etc/nginx/sites-available/penstation

    # Enable site
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/penstation /etc/nginx/sites-enabled/
    nginx -t && systemctl restart nginx
    log "Nginx configured and running"
}

# ── Setup Systemd Service ─────────────────────────────────
setup_service() {
    local user="${SUDO_USER:-pi}"
    log "Creating systemd service..."
    cat > /etc/systemd/system/penstation.service << SVCEOF
[Unit]
Description=PENSTATION — Autonomous Network Security Station
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$VENV_DIR/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=$VENV_DIR/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=penstation

# Security hardening
NoNewPrivileges=false
ProtectSystem=false

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable penstation
    log "Systemd service created and enabled"
}

# ── Setup Logrotate ────────────────────────────────────────
setup_logrotate() {
    log "Configuring log rotation..."
    cat > /etc/logrotate.d/penstation << 'LOGEOF'
/home/*/penstation/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}
LOGEOF
}

# ── Tailscale (Optional) ──────────────────────────────────
setup_tailscale() {
    echo ""
    read -rp "Install Tailscale for remote access? [y/N] " do_tailscale
    if [[ ! "$do_tailscale" =~ ^[Yy]$ ]]; then
        info "Skipping Tailscale"
        return
    fi

    log "Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
    log "Tailscale installed. Run 'sudo tailscale up' to authenticate."
}

# ── Create .env file ──────────────────────────────────────
create_env() {
    if [[ ! -f "$INSTALL_DIR/.env" ]]; then
        cp "$INSTALL_DIR/config.example.env" "$INSTALL_DIR/.env"
        log "Created .env from template"
    fi
}

# ── Final Screen ───────────────────────────────────────────
final_screen() {
    local ip
    ip=$(hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    cat << 'EOF'
    ╔═══════════════════════════════════════════════╗
    ║         PENSTATION INSTALLED SUCCESSFULLY     ║
    ╚═══════════════════════════════════════════════╝
EOF
    echo ""
    echo -e "  ${BOLD}Dashboard:${NC}    ${CYAN}http://$ip${NC}"
    echo -e "  ${BOLD}Direct API:${NC}   ${CYAN}http://$ip:8080${NC}"
    echo -e "  ${BOLD}Service:${NC}      ${GREEN}sudo systemctl start penstation${NC}"
    echo -e "  ${BOLD}Logs:${NC}         ${GREEN}journalctl -u penstation -f${NC}"
    echo -e "  ${BOLD}Config:${NC}       ${GREEN}$INSTALL_DIR/.env${NC}"
    echo -e "  ${BOLD}WiFi:${NC}         ${CYAN}Manage via web dashboard (WiFi button in header)${NC}"
    echo ""
    echo -e "  The scanner will start automatically on boot."
    echo -e "  First scan begins within 60 seconds of starting."
    echo -e "  Switch WiFi networks anytime from the dashboard."
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════
main() {
    banner
    check_root
    check_arch
    setup_wifi
    update_system
    install_deps
    install_nuclei
    create_env
    setup_python
    init_database
    setup_nginx
    setup_service
    setup_logrotate
    setup_tailscale
    systemctl start penstation
    final_screen
}

main "$@"
