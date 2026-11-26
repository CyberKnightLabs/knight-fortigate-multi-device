"""Load FortiGate device settings from MCP Manager and OS Keychain.

Author: Ehsan Emad (CyberKnightLabs)
"""

import json
import os
from pathlib import Path


CONFIG_DIR = Path.home() / ".config" / "fortigate-mcp-manager"
SSH_SERVICE = "fortigate-mcp-manager-ssh"
KNOWN_HOSTS = CONFIG_DIR / "known_hosts"


def get_managed_config(device_name=None):
    """Return connection settings for a registered FortiGate."""
    import keyring

    config_path = (
        Path.home()
        / ".config"
        / "fortigate-mcp-manager"
        / "config.json"
    )

    if not config_path.is_file():
        raise RuntimeError("FortiGate MCP Manager configuration not found.")

    config = json.loads(config_path.read_text(encoding="utf-8"))
    devices = config.get("devices", {})

    if not devices:
        raise RuntimeError("No FortiGate devices registered.")

    if not device_name:
        if len(devices) == 1:
            device_name = next(iter(devices))
        else:
            raise RuntimeError(
                "Multiple FortiGates registered. "
                "Set FORTIGATE_DEVICE to select one."
            )

    if device_name not in devices:
        raise RuntimeError(f"Unknown FortiGate device: {device_name}")

    device = devices[device_name]

    token = keyring.get_password(
        "fortigate-mcp-manager",
        device_name
    )

    if not token:
        raise RuntimeError(
            f"No Keychain API token found for {device_name}"
        )

    host = device["host"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    # Optional SSH access for diagnostics (debug / packet capture). The password
    # lives only in the Keychain (service fortigate-mcp-manager-ssh), set by the
    # user with `python ssh_setup.py <device>`.
    ssh = {
        "ssh_host": device["host"],
        "ssh_port": int(device.get("ssh_port", 22)),
        "ssh_username": device.get("ssh_username"),
        "ssh_password": keyring.get_password(SSH_SERVICE, device_name),
        "ssh_known_hosts": str(KNOWN_HOSTS) if KNOWN_HOSTS.is_file() else None,
    }

    return {
        **ssh,
        "host": f"https://{host}:{device['port']}",
        "api_token": token,
        "vdom": device["default_vdom"],
        "verify_ssl": (
            device.get("ca_cert")
            if device["verify_ssl"] and device.get("ca_cert")
            else device["verify_ssl"]
        ),
        "timeout": float(device["timeout"]),
    }
