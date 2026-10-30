"""Claude Desktop integration for FortiGate MCP Manager."""

import json
import shutil
from pathlib import Path

from ai_client_detection import detect_ai_clients


def build_claude_plan(mcp_location, device_name):
    """Prepare Claude Desktop MCP integration without changing files."""
    detection = detect_ai_clients()
    config_path = Path(detection["claude"]["config"])

    if not config_path.is_file():
        raise RuntimeError(
            "Claude Desktop configuration not found. "
            "Manual configuration-path selection is not implemented yet."
        )

    uv_path = shutil.which("uv")
    if not uv_path:
        raise RuntimeError("uv executable not found.")

    project = Path(mcp_location).expanduser().resolve()

    if not (project / "server.py").is_file():
        raise RuntimeError("MCP server.py not found.")

    if not (project / "pyproject.toml").is_file():
        raise RuntimeError("MCP pyproject.toml not found.")

    existing = json.loads(config_path.read_text(encoding="utf-8"))

    if not isinstance(existing, dict):
        raise RuntimeError("Invalid Claude configuration structure.")

    servers = existing.get("mcpServers", {})

    if not isinstance(servers, dict):
        raise RuntimeError("Invalid Claude MCP configuration.")

    entry = {
        "command": uv_path,
        "args": [
            "run",
            "--directory",
            str(project),
            "python",
            "server.py",
        ],
        "env": {
            "FORTIGATE_DEVICE": device_name,
        },
    }

    return {
        "client": "Claude Desktop",
        "registration": "fortigate-" + device_name,
        "config_path": str(config_path),
        "project": str(project),
        "device": device_name,
        "uv": uv_path,
        "action": "UPDATE" if "fortigate-" + device_name in servers else "ADD",
        "existing_servers": list(servers),
        "other_settings": [
            key for key in existing if key != "mcpServers"
        ],
        "entry": entry,
    }


if __name__ == "__main__":
    from manager import load_config

    config = load_config()

    if not isinstance(config, dict):
        raise SystemExit("[ERROR] Manager configuration unavailable.")

    devices = config.get("devices", {})

    if len(devices) != 1:
        raise SystemExit(
            "[ERROR] Exactly one FortiGate must be registered."
        )

    device_name = next(iter(devices))

    try:
        plan = build_claude_plan(
            config["mcp_location"],
            device_name,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"[ERROR] {exc}")

    print("\n========== CLAUDE INTEGRATION DRY RUN ==========")
    print("Client:", plan["client"])
    print("Action:", plan["action"])
    print("Configuration:", plan["config_path"])
    print("MCP project:", plan["project"])
    print("Executable:", plan["uv"])
    print("FortiGate:", plan["device"])
    print("Existing MCP servers:", len(plan["existing_servers"]))
    print("Other settings:", plan["other_settings"])
    print("API token in registration: NO")
    print("\n[OK] Integration plan generated.")
    print("[INFO] No configuration files modified.")


def apply_claude_plan(plan):
    """Update Claude's FortiGate entry after explicit user approval."""
    import os
    import tempfile
    from datetime import datetime

    config_path = Path(plan["config_path"])
    original = config_path.read_bytes()
    existing = json.loads(original.decode("utf-8"))

    if not isinstance(existing, dict):
        raise RuntimeError("Claude configuration must be a JSON object.")

    servers = existing.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise RuntimeError("Invalid Claude MCP configuration.")

    previous_servers = {
        name: value
        for name, value in servers.items()
        if name != plan["registration"]
    }
    previous_settings = {
        name: value
        for name, value in existing.items()
        if name != "mcpServers"
    }

    servers[plan["registration"]] = plan["entry"]
    existing["mcpServers"] = servers

    updated = (
        json.dumps(existing, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    validated = json.loads(updated)
    if validated["mcpServers"][plan["registration"]] != plan["entry"]:
        raise RuntimeError("FortiGate entry validation failed.")

    if {
        name: value
        for name, value in validated["mcpServers"].items()
        if name != plan["registration"]
    } != previous_servers:
        raise RuntimeError("Unrelated MCP registrations changed.")

    if {
        name: value
        for name, value in validated.items()
        if name != "mcpServers"
    } != previous_settings:
        raise RuntimeError("Unrelated Claude settings changed.")

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = config_path.with_name(
        f"{config_path.name}.backup-{timestamp}"
    )

    shutil.copy2(config_path, backup)
    if backup.read_bytes() != original:
        raise RuntimeError("Backup verification failed.")

    fd, temporary_name = tempfile.mkstemp(
        prefix=".fortigate-mcp-",
        dir=str(config_path.parent),
    )
    temporary = Path(temporary_name)

    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())

        shutil.copymode(config_path, temporary)
        os.replace(temporary, config_path)

        result = json.loads(config_path.read_text(encoding="utf-8"))

        if result != validated:
            raise RuntimeError("Post-write validation failed.")

    except Exception:
        if temporary.exists():
            temporary.unlink()

        if config_path.read_bytes() != original:
            shutil.copy2(backup, config_path)
        raise

    return str(backup)
