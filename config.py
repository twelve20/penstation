"""PENSTATION configuration."""

import os
from pathlib import Path
from pydantic_settings import BaseSettings


BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    # Network
    SUBNET: str = "auto"
    SCAN_INTERVAL_HOURS: int = 1
    TEMPLATE_UPDATE_HOUR: int = 3

    # WiFi
    WIFI_SSID: str = ""
    WIFI_PASSWORD: str = ""

    # Scanner
    NMAP_TIMING: str = "T3"
    NUCLEI_RATE_LIMIT: int = 50
    NUCLEI_TIMEOUT: int = 10
    SEVERITY_FILTER: str = "low,medium,high,critical"

    # Paths
    NUCLEI_BIN: str = "/usr/local/bin/nuclei"
    DB_PATH: str = str(BASE_DIR / "data" / "penstation.db")
    LOGS_DIR: str = str(BASE_DIR / "logs")

    # Alerts
    ALERT_ON_CRITICAL: bool = True
    ALERT_ON_NEW_HOST: bool = True

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8080

    model_config = {"env_file": str(BASE_DIR / ".env"), "env_file_encoding": "utf-8"}


settings = Settings()

# Ensure directories exist
os.makedirs(os.path.dirname(settings.DB_PATH), exist_ok=True)
os.makedirs(settings.LOGS_DIR, exist_ok=True)
