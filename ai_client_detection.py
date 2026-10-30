"""Cross-platform AI client detection for FortiGate MCP Manager."""

import os
import platform
import shutil
from pathlib import Path


def detect_ai_clients():
    system = platform.system()
    home = Path.home()

    if system == "Darwin":
        claude_config = (
            home / "Library/Application Support/Claude"
            / "claude_desktop_config.json"
        )
        claude_installed = (
            Path("/Applications/Claude.app").exists()
            or (home / "Applications/Claude.app").exists()
        )
    elif system == "Windows":
        appdata = Path(
            os.environ.get("APPDATA", str(home / "AppData/Roaming"))
        )
        claude_config = appdata / "Claude/claude_desktop_config.json"
        claude_installed = (
            (appdata / "Claude").exists()
            or shutil.which("Claude.exe") is not None
        )
    else:
        claude_config = (
            home / ".config/Claude/claude_desktop_config.json"
        )
        claude_installed = (
            shutil.which("claude-desktop") is not None
        )

    codex_home = Path(
        os.environ.get("CODEX_HOME", str(home / ".codex"))
    ).expanduser()

    codex_config = codex_home / "config.toml"
    codex_installed = (
        shutil.which("codex") is not None
        or codex_config.exists()
    )

    return {
        "os": system,
        "claude": {
            "installed": claude_installed,
            "config": str(claude_config),
            "config_exists": claude_config.is_file(),
        },
        "codex": {
            "installed": codex_installed,
            "config": str(codex_config),
            "config_exists": codex_config.is_file(),
        },
    }


if __name__ == "__main__":
    result = detect_ai_clients()

    print("\n========== AI Client Detection ==========")
    print("Operating system:", result["os"])

    for name in ("claude", "codex"):
        client = result[name]
        print(f"\n{name.title()} Desktop:" if name == "claude"
              else "\nOpenAI Codex:")
        print("Detected:", client["installed"])
        print("Configuration:", client["config"])
        print("Config exists:", client["config_exists"])
