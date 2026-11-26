"""SSH access for the diagnostics tools (debug, packet capture, read-only diagnose commands).

Used by the setup wizard (manager.py: "Add FortiGate Device" and "Manage FortiGate Devices >
Configure SSH Access") and runnable on its own:

    .venv/bin/python ssh_setup.py Forti-70G
    .venv/bin/python ssh_setup.py Forti-70G --port 2222
    .venv/bin/python ssh_setup.py Forti-70G --password   # change only the password
    .venv/bin/python ssh_setup.py Forti-70G --remove

The password is typed at a hidden prompt here, never into an AI chat. The flow:
1. read the FortiGate's SSH host key and show its fingerprint for you to confirm;
2. ask for the SSH username and password (hidden);
3. log in once (pinned to the confirmed host key) and run 'get system status';
4. only if the login works: save the host key to ~/.config/fortigate-mcp-manager/known_hosts
   (mode 600), the password in the OS Keychain (service "fortigate-mcp-manager-ssh"), and the
   username and port in the device entry of config.json (no password there).
Use a dedicated admin account with Trusted Hosts and a profile limited to what diagnostics need.

Author: Ehsan Emad (CyberKnightLabs)
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys

from manager_credentials import CONFIG_DIR, KNOWN_HOSTS, SSH_SERVICE

CONFIG = CONFIG_DIR / "config.json"


def _host_entry(host: str, port: int) -> str:
    return f"[{host}]:{port}" if port != 22 else host


async def _fetch_host_key(host: str, port: int):
    import asyncssh

    key = await asyncio.wait_for(asyncssh.get_server_host_key(host, port), timeout=15)
    if key is None:
        raise RuntimeError("could not read the SSH host key")
    return key


async def _login(host: str, port: int, username: str, password: str, known_hosts) -> str:
    """Log in once and return the 'Version:' line of get system status (no secrets)."""
    import asyncssh

    async with asyncssh.connect(host, port=port, username=username, password=password,
                                known_hosts=known_hosts, client_keys=None, agent_path=None,
                                connect_timeout=15) as conn:
        result = await conn.run("get system status", check=False, timeout=20)
        for line in str(result.stdout or "").splitlines():
            if line.strip().lower().startswith("version"):
                return line.strip()
        return "connected"


def _read_known_hosts() -> list[str]:
    return KNOWN_HOSTS.read_text().splitlines() if KNOWN_HOSTS.is_file() else []


def _write_known_hosts(lines: list[str]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    KNOWN_HOSTS.write_text("\n".join(lines) + ("\n" if lines else ""))
    KNOWN_HOSTS.chmod(0o600)


def ssh_status(name: str, device: dict) -> str:
    """One-line SSH status for listings (never shows the password)."""
    import keyring

    user = device.get("ssh_username")
    if not user:
        return "not configured"
    try:
        has_pw = keyring.get_password(SSH_SERVICE, name) is not None
    except Exception:  # noqa: BLE001
        has_pw = False
    port = int(device.get("ssh_port", 22))
    has_key = any(ln.startswith(_host_entry(device["host"], port) + " ") for ln in _read_known_hosts())
    missing = [w for w, ok in (("password", has_pw), ("host key", has_key)) if not ok]
    return f"{user}@port {port}" + (f" (missing: {', '.join(missing)})" if missing else "")


def configure_ssh(name: str, device: dict, port: int | None = None) -> bool:
    """Interactive SSH setup for one device. Updates `device` (ssh_username, ssh_port) in place;
    the caller saves config.json. Saves the host key and the Keychain password only after a
    successful login. Returns True when SSH was configured."""
    import keyring

    host = device["host"]
    default_port = int(device.get("ssh_port", 22))
    if port is None:
        answer = input(f"SSH port [{default_port}]: ").strip()
        try:
            port = int(answer or default_port)
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            print("[ERROR] Invalid SSH port.")
            return False

    try:
        key = asyncio.run(_fetch_host_key(host, port))
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] Could not reach SSH on {host}:{port} ({type(exc).__name__}). "
              "Check 'allowaccess ssh' on the interface and the admin-ssh-port.")
        return False
    fingerprint = key.get_fingerprint("sha256")
    print(f"SSH host key of {host}:{port}: {key.get_algorithm()} {fingerprint}")
    print("Compare it with the key you expect (console access or your inventory) before trusting it.")
    if input("Trust this host key? [y/N]: ").strip().lower() not in ("y", "yes"):
        print("[INFO] Host key not trusted; SSH not configured.")
        return False

    current_user = device.get("ssh_username", "")
    username = input(f"SSH admin username [{current_user}]: ").strip() or current_user
    if not username or any(c.isspace() for c in username):
        print("[ERROR] A username without spaces is required.")
        return False
    password = getpass.getpass("SSH password (hidden): ")
    if not password:
        print("[ERROR] A password is required.")
        return False

    import asyncssh

    entry_line = f"{_host_entry(host, port)} {key.export_public_key('openssh').decode().strip()}"
    print("Testing the SSH login...")
    try:
        banner = asyncio.run(_login(host, port, username, password, asyncssh.import_known_hosts(entry_line)))
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] SSH login failed ({type(exc).__name__}); nothing saved. Check the username, password, "
              "Trusted Hosts of the admin, and 'allowaccess ssh'.")
        password = None
        return False
    print(f"[OK] SSH login works ({banner}).")

    try:
        keyring.set_password(SSH_SERVICE, name, password)
        if keyring.get_password(SSH_SERVICE, name) != password:
            raise RuntimeError("verification failed")
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] Could not save the SSH password in the credential store ({type(exc).__name__}).")
        return False
    finally:
        password = None

    prefix = _host_entry(host, port) + " "
    _write_known_hosts([ln for ln in _read_known_hosts() if not ln.startswith(prefix)] + [entry_line])
    device["ssh_username"] = username
    device["ssh_port"] = port
    print("[OK] SSH password stored in the OS credential manager; host key saved.")
    return True


def change_ssh_password(name: str, device: dict) -> bool:
    """Replace only the SSH password (e.g. after it was changed on the FortiGate). Keeps the username,
    port and confirmed host key; the new password is saved only after a successful login."""
    import keyring

    if not device.get("ssh_username"):
        print("[ERROR] SSH is not configured for this device; use 'Configure SSH Access' first.")
        return False
    if not KNOWN_HOSTS.is_file():
        print("[ERROR] The SSH host key is missing; use 'Configure SSH Access' to confirm it again.")
        return False
    port = int(device.get("ssh_port", 22))
    print(f"SSH user {device['ssh_username']} on {device['host']}:{port}")
    password = getpass.getpass("New SSH password (hidden): ")
    if not password:
        print("[ERROR] Empty password; no changes made.")
        return False
    if getpass.getpass("Repeat the new SSH password (hidden): ") != password:
        print("[ERROR] The passwords do not match; no changes made.")
        password = None
        return False
    print("Testing the SSH login with the new password...")
    try:
        banner = asyncio.run(_login(device["host"], port, device["ssh_username"], password, str(KNOWN_HOSTS)))
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] SSH login failed ({type(exc).__name__}); the old password is kept.")
        password = None
        return False
    try:
        keyring.set_password(SSH_SERVICE, name, password)
        if keyring.get_password(SSH_SERVICE, name) != password:
            raise RuntimeError("verification failed")
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] Could not save the SSH password in the credential store ({type(exc).__name__}).")
        return False
    finally:
        password = None
    print(f"[OK] SSH login works ({banner}); new SSH password stored in the OS credential manager.")
    return True


def remove_ssh(name: str, device: dict) -> None:
    """Remove the SSH password, the host key entry and the SSH fields of one device."""
    import keyring

    try:
        keyring.delete_password(SSH_SERVICE, name)
    except Exception:  # noqa: BLE001 - nothing stored
        pass
    if "host" in device:
        prefix = _host_entry(device["host"], int(device.get("ssh_port", 22))) + " "
        lines = _read_known_hosts()
        kept = [ln for ln in lines if not ln.startswith(prefix)]
        if kept != lines:
            _write_known_hosts(kept)
    device.pop("ssh_username", None)
    device.pop("ssh_port", None)


def test_ssh(name: str, device: dict) -> tuple[bool, str]:
    """Log in with the stored SSH settings. Returns (ok, message); never prints the password."""
    import keyring

    if not device.get("ssh_username"):
        return False, "SSH not configured"
    password = keyring.get_password(SSH_SERVICE, name)
    if not password or not KNOWN_HOSTS.is_file():
        return False, "SSH password or host key missing; reconfigure SSH access"
    try:
        banner = asyncio.run(_login(device["host"], int(device.get("ssh_port", 22)), device["ssh_username"],
                                    password, str(KNOWN_HOSTS)))
        return True, banner
    except Exception as exc:  # noqa: BLE001
        return False, f"SSH login failed ({type(exc).__name__})"
    finally:
        password = None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("device", help="device name as registered in the manager, e.g. Forti-70G")
    ap.add_argument("--port", type=int, default=None, help="SSH port (asked when omitted)")
    ap.add_argument("--password", action="store_true", help="change only the SSH password")
    ap.add_argument("--remove", action="store_true", help="remove SSH access for this device")
    a = ap.parse_args()

    from manager import save_device_config

    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    device = config.get("devices", {}).get(a.device)
    if not device:
        print(f"Unknown device '{a.device}'. Registered: {', '.join(config.get('devices', {}))}")
        return 1
    if a.remove:
        remove_ssh(a.device, device)
        ok = save_device_config(config)
        print("[OK] SSH access removed." if ok else "[ERROR] Configuration not saved.")
        return 0 if ok else 1
    if a.password:
        return 0 if change_ssh_password(a.device, device) else 1
    if not configure_ssh(a.device, device, a.port):
        return 1
    if not save_device_config(config):
        return 1
    print(f"[OK] Saved. Restart the AI client so the {a.device} server picks up SSH access.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
