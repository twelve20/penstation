"""WiFi adapter detection and capability management."""

import asyncio
import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("penstation.wifi_adapters")


@dataclass
class WiFiAdapter:
    """WiFi adapter information and capabilities."""

    interface: str
    driver: str
    chipset: str
    supports_monitor: bool
    supports_injection: bool
    role: str  # "primary" (connectivity) or "attack" (pentesting)


async def detect_all_adapters() -> list[WiFiAdapter]:
    """
    Detect all WiFi adapters and their capabilities.

    Returns:
        List of WiFiAdapter objects with capability information
    """
    adapters = []

    # Get all WiFi interfaces
    proc = await asyncio.create_subprocess_exec(
        "iw", "dev",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    output = stdout.decode()

    # Parse interface names
    interfaces = re.findall(r"Interface\s+(\S+)", output)

    for iface in interfaces:
        logger.info(f"Detecting capabilities for {iface}")

        # Get driver and chipset info
        driver, chipset = await _get_driver_info(iface)

        # Test monitor mode support
        supports_monitor = await _test_monitor_mode(iface)

        # Test injection support (requires monitor mode)
        supports_injection = False
        if supports_monitor:
            supports_injection = await _test_injection(iface)

        # Assign role based on capabilities
        role = _assign_role(iface, driver, supports_monitor, supports_injection)

        adapter = WiFiAdapter(
            interface=iface,
            driver=driver,
            chipset=chipset,
            supports_monitor=supports_monitor,
            supports_injection=supports_injection,
            role=role,
        )

        adapters.append(adapter)
        logger.info(
            f"Adapter {iface}: driver={driver}, monitor={supports_monitor}, "
            f"injection={supports_injection}, role={role}"
        )

    return adapters


async def _get_driver_info(interface: str) -> tuple[str, str]:
    """Get driver and chipset information for interface."""
    try:
        # Try to get driver from /sys/class/net
        driver_path = Path(f"/sys/class/net/{interface}/device/driver/module")
        if driver_path.exists():
            driver = driver_path.resolve().name
        else:
            driver = "unknown"

        # Get chipset from lsusb or lspci
        chipset = "unknown"

        # Try USB devices
        proc = await asyncio.create_subprocess_exec(
            "lsusb",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        lsusb_output = stdout.decode()

        # Common chipset patterns
        chipset_patterns = {
            "Atheros": r"Atheros.*AR\d+",
            "Realtek": r"Realtek.*RTL\d+",
            "Broadcom": r"Broadcom.*BCM\d+",
            "Ralink": r"Ralink.*RT\d+",
            "MediaTek": r"MediaTek.*MT\d+",
        }

        for vendor, pattern in chipset_patterns.items():
            match = re.search(pattern, lsusb_output)
            if match:
                chipset = match.group(0)
                break

        return driver, chipset

    except Exception as e:
        logger.warning(f"Failed to get driver info for {interface}: {e}")
        return "unknown", "unknown"


async def _test_monitor_mode(interface: str) -> bool:
    """
    Test if adapter supports monitor mode.

    This is a non-destructive test that checks phy capabilities.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "iw", "phy",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()

        # Check if monitor mode is supported
        if "monitor" in output.lower():
            return True

        return False

    except Exception as e:
        logger.warning(f"Failed to test monitor mode for {interface}: {e}")
        return False


async def _test_injection(interface: str) -> bool:
    """
    Test if adapter supports packet injection.

    Note: This test requires the interface to be in monitor mode temporarily.
    We check the adapter capabilities instead of actual injection.
    """
    try:
        # Check if aireplay-ng is available
        proc = await asyncio.create_subprocess_exec(
            "which", "aireplay-ng",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        if proc.returncode != 0:
            logger.warning("aireplay-ng not found, cannot test injection")
            return False

        # Check driver - known good injection drivers
        driver_path = Path(f"/sys/class/net/{interface}/device/driver/module")
        if driver_path.exists():
            driver = driver_path.resolve().name

            # Drivers known to support injection
            injection_drivers = [
                "ath9k", "ath9k_htc", "rt2800usb", "rt73usb", "rtl8187",
                "brcmfmac",   # Broadcom with Nexmon patches (Kali)
                "rtl8xxxu",   # Realtek RTL8188/8192
                "rtl8188eus", # Realtek RTL8188EUS (aircrack-ng driver)
                "88XXau",     # Realtek RTL8812AU
                "8812au",     # Realtek RTL8812AU alt
            ]

            if driver in injection_drivers:
                logger.info(f"Driver {driver} is known to support injection")
                return True

        return False

    except Exception as e:
        logger.warning(f"Failed to test injection for {interface}: {e}")
        return False


def _assign_role(
    interface: str, driver: str, supports_monitor: bool, supports_injection: bool
) -> str:
    """
    Assign role to adapter based on capabilities.

    Rules:
    1. Built-in adapters (wlan0, driver=brcmfmac) -> primary (connectivity)
    2. External adapters with injection support -> attack (pentesting)
    3. External adapters without injection -> primary
    """
    # External USB adapters → prefer as attack adapter
    if interface != "wlan0" and supports_monitor:
        return "attack"

    # Built-in Raspberry Pi WiFi → primary for connectivity
    if interface == "wlan0":
        return "primary"

    # Any adapter with injection support → attack
    if supports_injection and supports_monitor:
        return "attack"

    # Default to primary for connectivity
    return "primary"


async def assign_adapter_roles() -> dict[str, str]:
    """
    Assign roles to all detected adapters.

    Returns:
        Dictionary mapping role to interface name:
        {"primary": "wlan0", "attack": "wlan1"}
    """
    adapters = await detect_all_adapters()

    roles = {}

    # Find primary adapter (for connectivity)
    primary_adapters = [a for a in adapters if a.role == "primary"]
    if primary_adapters:
        roles["primary"] = primary_adapters[0].interface
    elif adapters:
        # Fallback: use first adapter
        roles["primary"] = adapters[0].interface

    # Find attack adapter (for pentesting)
    attack_adapters = [a for a in adapters if a.role == "attack"]
    if attack_adapters:
        roles["attack"] = attack_adapters[0].interface
    else:
        # No dedicated attack adapter
        roles["attack"] = None

    logger.info(f"Assigned adapter roles: {roles}")
    return roles


async def enable_monitor_mode(interface: str) -> bool:
    """
    Enable monitor mode on adapter using airmon-ng.

    Args:
        interface: WiFi interface name

    Returns:
        True if successful, False otherwise
    """
    try:
        logger.info(f"Enabling monitor mode on {interface}")

        # Stop network managers that might interfere
        await asyncio.create_subprocess_exec(
            "airmon-ng", "check", "kill",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Enable monitor mode
        proc = await asyncio.create_subprocess_exec(
            "airmon-ng", "start", interface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            # airmon-ng creates a new interface like wlan0mon
            output = stdout.decode()
            match = re.search(r"monitor mode (?:vif )?enabled (?:for )?\[?(\S+)\]?", output, re.IGNORECASE)
            if match:
                mon_interface = match.group(1)
                logger.info(f"Monitor mode enabled: {mon_interface}")
                return True

        logger.error(f"Failed to enable monitor mode: {stderr.decode()}")
        return False

    except Exception as e:
        logger.error(f"Error enabling monitor mode: {e}")
        return False


async def disable_monitor_mode(interface: str) -> bool:
    """
    Disable monitor mode and restore managed mode.

    Args:
        interface: Monitor mode interface (e.g., wlan0mon)

    Returns:
        True if successful, False otherwise
    """
    try:
        logger.info(f"Disabling monitor mode on {interface}")

        proc = await asyncio.create_subprocess_exec(
            "airmon-ng", "stop", interface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            logger.info(f"Monitor mode disabled on {interface}")

            # Restart NetworkManager if it was killed
            await asyncio.create_subprocess_exec(
                "systemctl", "start", "NetworkManager",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            return True

        logger.error(f"Failed to disable monitor mode: {stderr.decode()}")
        return False

    except Exception as e:
        logger.error(f"Error disabling monitor mode: {e}")
        return False
