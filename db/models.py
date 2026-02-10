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
