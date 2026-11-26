"""FortiOS MCP Server — Complete REST API implementation.

This server exposes the entire Fortinet FortiOS REST API (written against 7.6.6)
(1536 endpoints across CMDB, Monitor, Log, and Service sections)
as Model Context Protocol tools.

Architecture:
- Generic CRUD tools (cover all 1536 endpoints directly)
- Specific typed tools (cover common operations)
- Async HTTP client with Bearer-token authentication

Configuration (environment variables or .env file):
    FORTIOS_HOST       — FortiGate URL (e.g. https://192.168.1.1)
    FORTIOS_API_TOKEN  — API Bearer token
    FORTIOS_VDOM       — VDOM (default: root)
    FORTIOS_VERIFY_SSL — true/false (default: false for self-signed)
    FORTIOS_TIMEOUT    — HTTP timeout in seconds (default: 30)
    FORTIOS_REDACT     — true/false (default: true) redact secrets in every response

Author: Ehsan Emad (CyberKnightLabs)
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from fortios_client import FortiOSClient
from ssh_runner import FortiSSH
from manager_credentials import get_managed_config

# ── Tool modules ──────────────────────────────────────────────────────
from tools import (
    diagnostics,
    extended,
    generic,
    system,
    firewall,
    vpn,
    router,
    user,
    monitor,
    log,
    security,
    wireless,
)

# Load .env if present
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("fortios_mcp")


# ─────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set. "
            f"Copy .env.example to .env and fill in your values."
        )
    return value


def _get_config() -> dict:
    # Prefer OS Keychain when managed-device mode is explicitly selected.
    device_name = os.environ.get("FORTIGATE_DEVICE", "").strip()
    if device_name:
        return get_managed_config(device_name)

    # Legacy environment-variable configuration.
    return {
        "host": _required_env("FORTIOS_HOST"),
        "api_token": _required_env("FORTIOS_API_TOKEN"),
        "vdom": os.environ.get("FORTIOS_VDOM", "root").strip(),
        "verify_ssl": os.environ.get("FORTIOS_VERIFY_SSL", "false").lower()
        in ("1", "true", "yes"),
        "timeout": float(os.environ.get("FORTIOS_TIMEOUT", "30")),
        # optional SSH for diagnostics (debug / packet capture)
        "ssh_host": os.environ.get("FORTIOS_SSH_HOST") or None,
        "ssh_port": int(os.environ.get("FORTIOS_SSH_PORT", "22")),
        "ssh_username": os.environ.get("FORTIOS_SSH_USERNAME") or None,
        "ssh_password": os.environ.get("FORTIOS_SSH_PASSWORD") or None,
        "ssh_known_hosts": os.environ.get("FORTIOS_SSH_KNOWN_HOSTS") or None,
    }


# ─────────────────────────────────────────────────────────────────────
# Lifespan — shared FortiOS client
# ─────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncGenerator[dict, None]:
    """Create and manage the FortiOS API client lifecycle."""
    cfg = _get_config()
    logger.info(
        "Connecting to FortiGate %s (vdom=%s, ssl-verify=%s)",
        cfg["host"],
        cfg["vdom"],
        cfg["verify_ssl"],
    )
    client = FortiOSClient(
        host=cfg["host"],
        api_token=cfg["api_token"],
        vdom=cfg["vdom"],
        verify_ssl=cfg["verify_ssl"],
        timeout=cfg["timeout"],
        redact_output=os.environ.get("FORTIOS_REDACT", "true").lower() not in ("0", "false", "no"),
    )
    ssh = FortiSSH(
        host=cfg.get("ssh_host"),
        port=int(cfg.get("ssh_port") or 22),
        username=cfg.get("ssh_username"),
        password=cfg.get("ssh_password"),
        known_hosts=cfg.get("ssh_known_hosts"),
    )
    logger.info("SSH diagnostics %s.", "enabled" if ssh.configured else "not configured (run ssh_setup.py)")
    async with client:
        logger.info("FortiOS client initialized.")
        yield {"client": client, "ssh": ssh}
    logger.info("FortiOS client closed.")


# ─────────────────────────────────────────────────────────────────────
# FastMCP application
# ─────────────────────────────────────────────────────────────────────

mcp = FastMCP(
    name="Knight FortiGate Multi-Device",
    host=os.environ.get("MCP_HOST", "127.0.0.1"),
    port=int(os.environ.get("MCP_PORT", "8000")),
    instructions=(
        "You are connected to a Fortinet FortiGate (FortiOS 7.x). "
        "Call device_info for the real model, serial and FortiOS version; do not assume a version. "
        "This server exposes the complete FortiOS REST API as MCP tools. "
        "\n\n"
        "Tool categories:\n"
        "- **Generic**: cmdb_list/get/create/update/delete, monitor_get/action, log_get, service_call\n"
        "    → These cover ALL 1536 FortiOS API endpoints directly.\n"
        "- **Extended**: device_info (live version/model/serial), cmdb_schema (field schema from the device), "
        "cmdb_patch (change only given fields: dry run diff, then write + read-back verify), "
        "cmdb_exists, cmdb_move and cmdb_clone (dry run by default, verified), api_directory (discover endpoints), "
        "log_search (POST log queries). cmdb_get/cmdb_list accept read options in 'params' "
        "(datasource, with_meta, skip, scope, exclude-default-values, key/pattern, action=schema|meta|revision).\n"
        "- **Diagnostics (SSH)**: cpu_usage, diag_command (read-only allowlist), debug_flow, debug_ike, "
        "debug_application, packet_capture, debug_reset. Enforced: CPU check first (debug refused at >=95%, "
        "capture at >=90%), filters required, max 10 packets (100 when CPU <50%), debug always disabled at the end. "
        "Interactive: tell the user to generate the traffic before you call a debug or capture tool.\n"
        "- **System**: interfaces, DNS, NTP, admins, DHCP, SNMP, certificates, VDOMs\n"
        "- **Firewall**: policies, addresses, services, VIPs, IP pools, schedules, sessions\n"
        "- **VPN**: IPsec Phase 1/2, SSL VPN portals/settings, tunnel control, certificates\n"
        "- **Router**: static routes, OSPF, BGP, RIP, prefix lists, route maps, SD-WAN\n"
        "- **User**: local users, groups, RADIUS, LDAP, TACACS+, SAML, session management\n"
        "- **Monitor**: ARP, FortiView, license, endpoint, IPS, switch controller, config backup\n"
        "- **Log**: traffic/event/virus/webfilter/IPS logs, FortiAnalyzer config\n"
        "- **Security**: IPS, AV, webfilter, app control, DLP, email filter, DNS filter, WAF, ZTNA\n"
        "- **Wireless**: APs, SSIDs, Hotspot 2.0, connected clients, rogue AP detection\n"
        "\n"
        "Secret values (passwords, PSKs, keys, ENC values) are redacted as <REDACTED> in every response "
        "and can never be written back. "
        "Prefer cmdb_patch over cmdb_update for changing existing objects. "
        "Always use specific typed tools when available. "
        "Fall back to generic cmdb_list/cmdb_get/monitor_get for unlisted resources. "
        "For destructive operations (delete, policy changes), confirm with the user first."
    ),
    lifespan=lifespan,
)

# ─────────────────────────────────────────────────────────────────────
# Register all tool modules
# ─────────────────────────────────────────────────────────────────────

diagnostics.register(mcp)
extended.register(mcp)
generic.register(mcp)
system.register(mcp)
firewall.register(mcp)
vpn.register(mcp)
router.register(mcp)
user.register(mcp)
monitor.register(mcp)
log.register(mcp)
security.register(mcp)
wireless.register(mcp)

logger.info("All 12 tool modules registered (255 tools).")


# ─────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────


def main() -> None:
    """Run the MCP server using stdio transport (default for Claude Desktop)."""
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "streamable-http":
        host = os.environ.get("MCP_HOST", "127.0.0.1")
        port = int(os.environ.get("MCP_PORT", "8000"))
        logger.info("Starting FortiOS MCP Server on %s:%d (HTTP)", host, port)
        mcp.run(transport="streamable-http")
    else:
        logger.info("Starting FortiOS MCP Server on stdio")
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
