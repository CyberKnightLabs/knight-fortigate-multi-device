"""Load FortiGate device settings from MCP Manager and OS Keychain."""

import json
import os
from pathlib import Path


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

    return {
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
