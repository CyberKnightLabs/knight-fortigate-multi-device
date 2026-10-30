"""Safe AI client integration for FortiGate MCP Manager."""

import os
import shutil
import tomllib
from pathlib import Path

from ai_client_detection import detect_ai_clients


def build_codex_plan(mcp_location, device_name):
    """Prepare a Codex MCP registration without writing files."""
    detection = detect_ai_clients()
    config_path = Path(detection["codex"]["config"])

    if not config_path.is_file():
        raise RuntimeError(
            "Codex configuration not found. "
            "Install/configure Codex before integration."
        )

    uv_path = shutil.which("uv")
    if not uv_path:
        raise RuntimeError("uv executable not found in PATH.")

    project = Path(mcp_location).expanduser().resolve()

    if not (project / "server.py").is_file():
        raise RuntimeError("MCP server.py not found.")

    if not (project / "pyproject.toml").is_file():
        raise RuntimeError("MCP pyproject.toml not found.")

    with config_path.open("rb") as handle:
        existing = tomllib.load(handle)

    servers = existing.get("mcp_servers", {})
    if not isinstance(servers, dict):
        raise RuntimeError("Invalid Codex MCP configuration.")

    existing_entry = servers.get("fortigate-" + device_name)

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
        "client": "OpenAI Codex",
        "registration": "fortigate-" + device_name,
        "config_path": str(config_path),
        "project": str(project),
        "device": device_name,
        "uv": uv_path,
        "action": "UPDATE" if existing_entry else "ADD",
        "existing_servers": list(servers),
        "entry": entry,
    }


if __name__ == "__main__":
    from manager import load_config

    config = load_config()
    if not isinstance(config, dict):
        raise SystemExit("[ERROR] Manager configuration unavailable.")

    devices = config.get("devices", {})
    if not devices:
        raise SystemExit("[ERROR] No FortiGate devices registered.")

    if len(devices) != 1:
        raise SystemExit(
            "[ERROR] Multiple FortiGates registered. "
            "Device selection is required."
        )

    device_name = next(iter(devices))

    try:
        plan = build_codex_plan(
            config["mcp_location"],
            device_name,
        )
    except (OSError, ValueError, RuntimeError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit(f"[ERROR] {exc}")

    print("\n========== CODEX INTEGRATION DRY RUN ==========")
    print("Client:", plan["client"])
    print("Action:", plan["action"])
    print("Configuration:", plan["config_path"])
    print("MCP project:", plan["project"])
    print("Executable:", plan["uv"])
    print("FortiGate:", plan["device"])
    print("Existing MCP servers:", len(plan["existing_servers"]))
    print("API token in registration: NO")
    print("\n[OK] Integration plan generated.")
    print("[INFO] No configuration files modified.")


def apply_codex_plan(plan):
    """Safely add FortiGate MCP to Codex after user confirmation."""
    import json
    import tempfile
    from datetime import datetime

    config_path = Path(plan["config_path"])
    original = config_path.read_bytes()
    current = tomllib.loads(original.decode("utf-8"))

    if plan["registration"] in current.get("mcp_servers", {}):
        raise RuntimeError(
            "An existing FortiGate MCP registration was detected. "
            "Update support is not enabled yet."
        )

    entry = plan["entry"]
    args = json.dumps(entry["args"])
    command = json.dumps(entry["command"])
    device = json.dumps(entry["env"]["FORTIGATE_DEVICE"])

    addition = (
        f"\n\n[mcp_servers.{json.dumps(plan['registration'])}]\n"
        f"command = {command}\n"
        f"args = {args}\n"
        f"\n[mcp_servers.{json.dumps(plan['registration'])}.env]\n"
        f"FORTIGATE_DEVICE = {device}\n"
    )

    updated = original.rstrip(b"\r\n") + addition.encode("utf-8")

    parsed = tomllib.loads(updated.decode("utf-8"))
    if parsed["mcp_servers"][plan["registration"]] != entry:
        raise RuntimeError("Generated Codex configuration failed validation.")

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = config_path.with_name(
        f"{config_path.name}.backup-{timestamp}"
    )

    if backup.exists():
        raise RuntimeError("Backup path already exists.")

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

        verified = tomllib.loads(
            config_path.read_text(encoding="utf-8")
        )
        if verified["mcp_servers"][plan["registration"]] != entry:
            raise RuntimeError("Post-write validation failed.")

    except Exception:
        if temporary.exists():
            temporary.unlink()

        # Restore only if the original file was replaced.
        if config_path.read_bytes() != original:
            shutil.copy2(backup, config_path)
        raise

    return str(backup)
