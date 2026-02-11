"""SQLAlchemy models for PENSTATION."""

from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Boolean,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), unique=True, nullable=False, index=True)
    mac = Column(String(17), default="")
    mac_vendor = Column(String(128), default="")
    hostname = Column(String(255), default="")
    os_name = Column(String(128), default="")
    os_version = Column(String(128), default="")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(16), default="new")  # active / inactive / new
    risk_score = Column(Integer, default=0)

    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    vulns = relationship(
        "Vulnerability", back_populates="host", cascade="all, delete-orphan"
    )


class Port(Base):
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_ip = Column(String(45), ForeignKey("hosts.ip", ondelete="CASCADE"), nullable=False, index=True)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(8), default="tcp")
    service = Column(String(64), default="")
    version = Column(String(128), default="")
    state = Column(String(16), default="open")
    last_seen = Column(DateTime, default=datetime.utcnow)

    host = relationship("Host", back_populates="ports")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_ip = Column(String(45), ForeignKey("hosts.ip", ondelete="CASCADE"), nullable=False, index=True)
    port_number = Column(Integer, default=0)
    cve_id = Column(String(32), default="")
    template_id = Column(String(128), default="")
    severity = Column(String(16), default="info")  # critical/high/medium/low/info
    name = Column(String(255), default="")
    description = Column(Text, default="")
    remediation = Column(Text, default="")
    reference_url = Column(String(512), default="")
    found_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String(16), default="active")  # active / fixed / acknowledged

    host = relationship("Host", back_populates="vulns")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(32), nullable=False)  # discovery/portscan/vulnscan/update
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0)
    hosts_scanned = Column(Integer, default=0)
    ports_found = Column(Integer, default=0)
    vulns_found = Column(Integer, default=0)
    status = Column(String(16), default="running")  # running/completed/failed
    error_message = Column(Text, default="")


class CVEEntry(Base):
    __tablename__ = "cve_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(32), unique=True, nullable=False, index=True)
    description = Column(Text, default="")
    cvss_score = Column(Float, default=0.0)
    severity = Column(String(16), default="info")
    published_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    alert_type = Column(String(32), default="vuln")  # vuln / new_host / scan_complete
    host_ip = Column(String(45), default="")
    severity = Column(String(16), default="info")
    message = Column(Text, default="")
    acknowledged = Column(Boolean, default=False)


# ── WiFi Pentesting Tables ────────────────────────────────


class WiFiNetwork(Base):
    """WiFi networks discovered during scanning."""

    __tablename__ = "wifi_networks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ssid = Column(String(255), nullable=False)
    bssid = Column(String(17), unique=True, nullable=False, index=True)  # MAC address
    channel = Column(Integer, default=0)
    frequency = Column(Integer, default=0)  # MHz
    encryption = Column(String(32), default="")  # WPA2, WPA3, WEP, Open
    signal = Column(Integer, default=0)  # dBm or percentage
    clients_count = Column(Integer, default=0)
    wps_enabled = Column(Boolean, default=False)
    wps_locked = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    clients = relationship("WiFiClient", back_populates="network", cascade="all, delete-orphan")
    handshakes = relationship("WiFiHandshake", back_populates="network", cascade="all, delete-orphan")


class WiFiClient(Base):
    """WiFi clients (stations) connected to networks."""

    __tablename__ = "wifi_clients"

    id = Column(Integer, primary_key=True, autoincrement=True)
    mac = Column(String(17), unique=True, nullable=False, index=True)
    vendor = Column(String(128), default="")
    connected_to_bssid = Column(String(17), ForeignKey("wifi_networks.bssid", ondelete="SET NULL"), nullable=True)
    signal = Column(Integer, default=0)
    probe_requests = Column(Text, default="")  # JSON array of SSIDs
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    network = relationship("WiFiNetwork", back_populates="clients")


class WiFiHandshake(Base):
    """Captured WPA/WPA2 handshakes for offline cracking."""

    __tablename__ = "wifi_handshakes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ssid = Column(String(255), nullable=False)
    bssid = Column(String(17), ForeignKey("wifi_networks.bssid", ondelete="CASCADE"), nullable=False, index=True)
    capture_type = Column(String(16), default="")  # full, half, PMKID
    pcap_path = Column(String(512), nullable=False)
    captured_at = Column(DateTime, default=datetime.utcnow)
    cracked = Column(Boolean, default=False)
    password = Column(String(255), default="")  # If cracked

    network = relationship("WiFiNetwork", back_populates="handshakes")


class WiFiAttack(Base):
    """Log of WiFi attack activities."""

    __tablename__ = "wifi_attacks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    attack_type = Column(String(32), nullable=False)  # deauth, beacon_flood, wps_reaver, etc.
    target_bssid = Column(String(17), default="")
    target_client_mac = Column(String(17), default="")
    status = Column(String(16), default="running")  # running, completed, failed
    packets_sent = Column(Integer, default=0)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)


# ── Network Attack Tables ──────────────────────────────────


class BruteForceResult(Base):
    """Results from brute force attacks on network services."""

    __tablename__ = "brute_force_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_ip = Column(String(45), ForeignKey("hosts.ip", ondelete="CASCADE"), nullable=False, index=True)
    service = Column(String(32), nullable=False)  # ssh, ftp, rdp, smb, etc.
    port = Column(Integer, nullable=False)
    username = Column(String(255), default="")
    password = Column(String(255), default="")
    success = Column(Boolean, nullable=False)
    found_at = Column(DateTime, default=datetime.utcnow)


class StolenFile(Base):
    """Files exfiltrated from vulnerable shares."""

    __tablename__ = "stolen_files"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_ip = Column(String(45), ForeignKey("hosts.ip", ondelete="CASCADE"), nullable=False, index=True)
    service = Column(String(32), default="")  # smb, ftp, nfs
    file_path = Column(String(1024), nullable=False)  # Original path on target
    local_path = Column(String(1024), nullable=False)  # Local path on PENSTATION
    file_size = Column(Integer, default=0)  # Bytes
    stolen_at = Column(DateTime, default=datetime.utcnow)


# ── Bluetooth Tables ───────────────────────────────────────


class BluetoothDevice(Base):
    """Bluetooth and BLE devices discovered."""

    __tablename__ = "bluetooth_devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    mac = Column(String(17), unique=True, nullable=False, index=True)
    name = Column(String(255), default="")
    device_type = Column(String(8), default="BT")  # BT or BLE
    vendor = Column(String(128), default="")
    rssi = Column(Integer, default=0)  # Signal strength
    services = Column(Text, default="")  # JSON array of UUIDs
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ── Plugin System Tables ───────────────────────────────────


class Plugin(Base):
    """Installed plugins."""

    __tablename__ = "plugins"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    version = Column(String(32), default="")
    author = Column(String(128), default="")
    description = Column(Text, default="")
    enabled = Column(Boolean, default=False)
    config = Column(Text, default="{}")  # JSON configuration
    installed_at = Column(DateTime, default=datetime.utcnow)
