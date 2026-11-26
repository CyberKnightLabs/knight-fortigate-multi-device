#!/usr/bin/env python3
"""FortiGate MCP Manager — interactive setup wizard.

Author: Ehsan Emad (CyberKnightLabs)
"""

import json
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "fortigate-mcp-manager"
CONFIG_FILE = CONFIG_DIR / "config.json"

MENU = """
====================================================
               FORTIGATE MCP MANAGER
            by Ehsan Emad - CyberKnightLabs
====================================================

 1. Set / Edit MCP Location
 2. Check & Install Prerequisites
 3. Add FortiGate Device
 4. Manage FortiGate Devices
 5. Test FortiGate Connectivity
 6. One-Click AI Client Integration
 7. Verify Installation & Diagnostics
 8. Update MCP Server
 9. Backup / Restore Configuration
10. Uninstall MCP Integration

 0. Exit
====================================================
"""


def load_config():
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        print("Configuration cannot be read. No changes made.")
        return None


def set_mcp_location():
    config = load_config()
    if config is None:
        return

    current = config.get("mcp_location")
    if current:
        print(f"\nCurrent MCP location: {current}")

    location = input("Enter MCP location: ").strip()
    if not location:
        print("No changes made.")
        return

    path = Path(location).expanduser().resolve()
    if not path.is_dir():
        print("Error: Directory does not exist.")
        return

    if not (path / "server.py").is_file():
        print("Error: server.py not found in this directory.")
        return

    if not (path / "pyproject.toml").is_file():
        print("Error: pyproject.toml not found in this directory.")
        return

    config["mcp_location"] = str(path)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    CONFIG_FILE.write_text(
        json.dumps(config, indent=2) + "\n", encoding="utf-8"
    )
    CONFIG_FILE.chmod(0o600)
    print(f"\n[OK] MCP location saved: {path}")



def check_prerequisites():
    """Check tools and prepare the MCP Python environment."""
    import shutil
    import subprocess
    import sys

    print("\n========== Prerequisite Check ==========")

    config = load_config()
    if config is None:
        return

    location = config.get("mcp_location")
    if not location:
        print("[ERROR] Configure MCP location using Option 1 first.")
        return

    mcp_dir = Path(location)
    if not (mcp_dir / "pyproject.toml").is_file():
        print("[ERROR] Invalid MCP project directory.")
        return

    python_ok = sys.version_info >= (3, 11)
    print(f"[{'OK' if python_ok else 'FAIL'}] Python: {sys.version.split()[0]}")
    if not python_ok:
        print("Python 3.11 or newer is required.")

    git = shutil.which("git")
    print(f"[{'OK' if git else 'MISSING'}] Git: {git or 'not found'}")

    uv = shutil.which("uv")
    print(f"[{'OK' if uv else 'MISSING'}] uv: {uv or 'not found'}")

    if not python_ok or not git:
        print("\nInstall or upgrade the missing prerequisites first.")
        return

    if not uv:
        answer = input("Install uv automatically? [y/N]: ").strip().lower()
        if answer != "y":
            print("Installation skipped.")
            return

        # Install uv through the Python package installer.
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--user", "uv"],
            check=False
        )
        if result.returncode != 0:
            print("[ERROR] uv installation failed.")
            return

        uv = shutil.which("uv")
        if not uv:
            print("[ERROR] uv installed but is not on PATH.")
            print("Restart Terminal or add its installation directory to PATH.")
            return

    print("\nSynchronizing MCP dependencies...")
    result = subprocess.run(
        [uv, "sync", "--directory", str(mcp_dir)],
        check=False
    )

    if result.returncode == 0:
        print("\n[OK] MCP prerequisites and dependencies are ready.")
    else:
        print("\n[ERROR] Dependency synchronization failed.")


def add_fortigate_device():
    """Register a FortiGate and store its API token securely."""
    import getpass
    import ipaddress
    import os
    import re
    import tempfile
    import keyring

    print("\n========== Add FortiGate Device ==========")

    config = load_config()
    if config is None:
        return

    devices = config.setdefault("devices", {})

    name = input("Device name: ").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
        print("[ERROR] Use 1-64 letters, numbers, hyphens or underscores.")
        return
    if name in devices:
        print("[ERROR] Device name already exists.")
        return

    host = input("Management IP / FQDN: ").strip()
    if not host or any(c.isspace() or c in "/@\\" for c in host):
        print("[ERROR] Enter an IP address or hostname, without a URL scheme.")
        return

    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(
            r"(?=.{1,253}$)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*", host
        ):
            print("[ERROR] Invalid hostname.")
            return

    try:
        port = int(input("HTTPS port [443]: ").strip() or "443")
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        print("[ERROR] Invalid HTTPS port.")
        return

    token = getpass.getpass("FortiGate API token (hidden): ").strip()
    if not token:
        print("[ERROR] API token is required.")
        return

    vdom = input("Default VDOM [root]: ").strip() or "root"
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", vdom):
        print("[ERROR] Invalid VDOM name.")
        return

    ssl_answer = input("Verify SSL certificates? [Y/n]: ").strip().lower()
    if ssl_answer not in ("", "y", "yes", "n", "no"):
        print("[ERROR] Invalid SSL selection.")
        return
    verify_ssl = ssl_answer not in ("n", "no")

    ca_cert = ""
    if verify_ssl:
        ca_cert = input("Custom CA certificate path [optional]: ").strip()
        if ca_cert:
            ca_path = Path(ca_cert).expanduser().resolve()
            if not ca_path.is_file():
                print("[ERROR] CA certificate file not found.")
                return
            ca_cert = str(ca_path)

    try:
        timeout = int(input("Connection timeout [30]: ").strip() or "30")
        if not 1 <= timeout <= 300:
            raise ValueError
    except ValueError:
        print("[ERROR] Timeout must be between 1 and 300 seconds.")
        return

    credential_service = "fortigate-mcp-manager"
    try:
        keyring.set_password(credential_service, name, token)
        if keyring.get_password(credential_service, name) != token:
            raise RuntimeError("Credential verification failed.")
    except Exception as exc:
        print(f"[ERROR] Could not securely save API token: {type(exc).__name__}")
        return
    finally:
        token = None

    devices[name] = {
        "host": host,
        "port": port,
        "default_vdom": vdom,
        "verify_ssl": verify_ssl,
        "ca_cert": ca_cert,
        "timeout": timeout
    }

    print("\n---------- SSH access (SSH module) ----------")
    print("SSH enables the troubleshooting tools that have no REST API: flow / IKE /")
    print("application debug, packet capture and read-only diagnose commands.")
    print("You will be asked for the SSH port, username and password (hidden).")
    ssh_answer = input("Configure SSH access now? [Y/n]: ").strip().lower()
    ssh_ok = False
    if ssh_answer in ("", "y", "yes"):
        from ssh_setup import configure_ssh

        ssh_ok = configure_ssh(name, devices[name])
        if not ssh_ok:
            print("[INFO] Continuing without SSH. Add it later: Manage FortiGate Devices > Configure SSH Access.")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=CONFIG_DIR,
            prefix=".config-",
            delete=False
        ) as temp:
            temporary_path = Path(temp.name)
            os.chmod(temporary_path, 0o600)
            json.dump(config, temp, indent=2)
            temp.write("\n")
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temporary_path, CONFIG_FILE)
        CONFIG_FILE.chmod(0o600)
    except OSError:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        keyring.delete_password(credential_service, name)
        print("[ERROR] Device configuration could not be saved.")
        return

    print(f"\n[OK] FortiGate '{name}' registered.")
    print("[OK] API token stored in OS credential manager.")
    print(f"[OK] Default VDOM: {vdom}")
    if ssh_ok:
        print(f"[OK] SSH access: {devices[name]['ssh_username']} on port {devices[name]['ssh_port']}")
    else:
        print("[INFO] SSH access: not configured (debug / packet capture tools disabled).")
    print("[INFO] API connectivity has not been tested yet.")


def save_device_config(config):
    """Atomically save configuration without exposing credentials."""
    import os
    import tempfile

    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=CONFIG_DIR,
            prefix=".config-",
            delete=False
        ) as temp:
            temp_path = Path(temp.name)
            os.chmod(temp_path, 0o600)
            json.dump(config, temp, indent=2)
            temp.write("\n")
            temp.flush()
            os.fsync(temp.fileno())

        os.replace(temp_path, CONFIG_FILE)
        CONFIG_FILE.chmod(0o600)
        return True

    except OSError as exc:
        print(f"[ERROR] Could not save configuration: {exc}")
        return False

    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def select_fortigate_device(devices):
    """Select a registered device by number."""
    if not devices:
        print("[INFO] No FortiGate devices registered.")
        return None

    names = sorted(devices)

    print("\nRegistered FortiGate Devices:")
    for index, name in enumerate(names, 1):
        print(f" {index}. {name}")

    choice = input("Select device number [0 to cancel]: ").strip()

    if choice == "0" or not choice:
        return None

    try:
        index = int(choice)
        if 1 <= index <= len(names):
            return names[index - 1]
    except ValueError:
        pass

    print("[ERROR] Invalid device selection.")
    return None


def list_fortigate_devices(devices):
    """Display registered devices without revealing API tokens."""
    if not devices:
        print("[INFO] No FortiGate devices registered.")
        return

    print("\n========== Registered FortiGates ==========")

    for name in sorted(devices):
        device = devices[name]
        print(f"\nDevice:       {name}")
        print(f"Management:   {device['host']}:{device['port']}")
        print(f"Default VDOM: {device['default_vdom']}")
        print(f"Verify SSL:   {device['verify_ssl']}")
        print(f"CA Cert:      {device.get('ca_cert') or 'Default'}")
        print(f"Timeout:      {device['timeout']} seconds")
        try:
            from ssh_setup import ssh_status

            print(f"SSH:          {ssh_status(name, device)}")
        except ImportError:
            print("SSH:          unknown (run the manager from the project virtualenv)")

    print("\n[INFO] API tokens and SSH passwords are never displayed.")


def edit_fortigate_device(config):
    """Edit nonsecret settings of a registered FortiGate."""
    devices = config.get("devices", {})
    name = select_fortigate_device(devices)
    if name is None:
        return

    import ipaddress
    import re

    current = devices[name]
    updated = current.copy()

    print(f"\nEditing {name}")
    print("Press Enter to keep the current value.")

    host = input(f"Management IP / FQDN [{current['host']}]: ").strip()
    if host:
        if any(c.isspace() or c in "/@\\" for c in host):
            print("[ERROR] Invalid management address.")
            return
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(
                r"(?=.{1,253}$)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*",
                host
            ):
                print("[ERROR] Invalid hostname.")
                return
        updated["host"] = host

    port = input(f"HTTPS port [{current['port']}]: ").strip()
    if port:
        try:
            value = int(port)
            if not 1 <= value <= 65535:
                raise ValueError
            updated["port"] = value
        except ValueError:
            print("[ERROR] Invalid port.")
            return

    vdom = input(
        f"Default VDOM [{current['default_vdom']}]: "
    ).strip()
    if vdom:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", vdom):
            print("[ERROR] Invalid VDOM.")
            return
        updated["default_vdom"] = vdom

    ssl = input(
        f"Verify SSL [{'Y' if current['verify_ssl'] else 'N'}] "
        "(y/n, Enter to keep): "
    ).strip().lower()

    if ssl:
        if ssl not in ("y", "yes", "n", "no"):
            print("[ERROR] Invalid SSL selection.")
            return
        updated["verify_ssl"] = ssl in ("y", "yes")

    if updated["verify_ssl"]:
        ca = input(
            f"Custom CA path [{current.get('ca_cert') or 'none'}] "
            "(Enter to keep, - to clear): "
        ).strip()
        if ca == "-":
            updated["ca_cert"] = ""
        elif ca:
            ca_path = Path(ca).expanduser().resolve()
            if not ca_path.is_file():
                print("[ERROR] CA certificate file not found.")
                return
            updated["ca_cert"] = str(ca_path)
    else:
        updated["ca_cert"] = ""

    timeout = input(
        f"Connection timeout [{current['timeout']}]: "
    ).strip()

    if timeout:
        try:
            value = int(timeout)
            if not 1 <= value <= 300:
                raise ValueError
            updated["timeout"] = value
        except ValueError:
            print("[ERROR] Invalid timeout.")
            return

    if updated == current:
        print("[INFO] No changes made.")
        return

    config["devices"][name] = updated

    if save_device_config(config):
        print(f"[OK] Device '{name}' updated.")
        if updated["host"] != current["host"] and current.get("ssh_username"):
            print("[WARNING] The management address changed: run 'Configure SSH Access' again so the")
            print("          new SSH host key is confirmed and saved.")


def update_fortigate_token(config):
    """Replace a FortiGate API token in the OS credential store."""
    import getpass
    import keyring

    name = select_fortigate_device(config.get("devices", {}))
    if name is None:
        return

    token = getpass.getpass(
        f"Enter new API token for {name} (hidden): "
    ).strip()

    if not token:
        print("[ERROR] Empty token. No changes made.")
        return

    try:
        keyring.set_password("fortigate-mcp-manager", name, token)
        if keyring.get_password("fortigate-mcp-manager", name) != token:
            print("[ERROR] Credential verification failed.")
            return
        print(f"[OK] API token updated securely for '{name}'.")
    except Exception as exc:
        print(f"[ERROR] Keychain operation failed: {type(exc).__name__}")
    finally:
        token = None


def remove_fortigate_device(config):
    """Remove device metadata and its stored API token."""
    import keyring

    name = select_fortigate_device(config.get("devices", {}))
    if name is None:
        return

    confirm = input(
        f"Type DELETE to remove '{name}', its API token and its SSH access: "
    ).strip()

    if confirm != "DELETE":
        print("[INFO] Removal cancelled.")
        return

    try:
        keyring.delete_password("fortigate-mcp-manager", name)
    except keyring.errors.PasswordDeleteError:
        print("[WARNING] No Keychain credential found.")
    except Exception as exc:
        print(f"[ERROR] Could not remove credential: {type(exc).__name__}")
        return

    try:
        from ssh_setup import remove_ssh

        remove_ssh(name, config["devices"][name])
    except Exception as exc:
        print(f"[WARNING] Could not remove SSH credentials: {type(exc).__name__}")

    del config["devices"][name]

    if save_device_config(config):
        print(f"[OK] Device '{name}' removed.")
    else:
        print("[WARNING] Configuration save failed; review device state.")


def configure_ssh_access(config):
    """Add or replace SSH access (port, username, password) for a registered FortiGate."""
    name = select_fortigate_device(config.get("devices", {}))
    if name is None:
        return
    try:
        from ssh_setup import configure_ssh
    except ImportError:
        print("[ERROR] SSH support needs the project dependencies (asyncssh). Run the manager with")
        print("        the project virtualenv: .venv/bin/python manager.py")
        return
    device = config["devices"][name]
    print(f"\nSSH access for {name} ({device['host']})")
    print("Use a dedicated admin with Trusted Hosts; the password is stored in the OS credential manager.")
    if configure_ssh(name, device) and save_device_config(config):
        print(f"[OK] SSH access saved for '{name}'. Restart the AI client to enable the diagnostics tools.")


def change_ssh_password(config):
    """Replace the stored SSH password after it was changed on the FortiGate."""
    name = select_fortigate_device(config.get("devices", {}))
    if name is None:
        return
    try:
        from ssh_setup import change_ssh_password as change
    except ImportError:
        print("[ERROR] SSH support needs the project dependencies (asyncssh). Run: uv run python manager.py")
        return
    if change(name, config["devices"][name]):
        print(f"[OK] SSH password updated for '{name}'. Restart the AI client so it uses the new password.")


def remove_ssh_access(config):
    """Remove SSH access (Keychain password, host key, username/port) for a FortiGate."""
    name = select_fortigate_device(config.get("devices", {}))
    if name is None:
        return
    from ssh_setup import remove_ssh

    if input(f"Remove SSH access for '{name}'? [y/N]: ").strip().lower() not in ("y", "yes"):
        print("[INFO] Cancelled.")
        return
    remove_ssh(name, config["devices"][name])
    if save_device_config(config):
        print(f"[OK] SSH access removed for '{name}'.")


def manage_fortigate_devices():
    """Interactive submenu for FortiGate device management."""
    while True:
        print("""
========== Manage FortiGate Devices ==========

 1. List Registered Devices
 2. Edit Device Settings
 3. Update API Token
 4. Remove Device
 5. Configure SSH Access (port, username, password)
 6. Change SSH Password
 7. Remove SSH Access
 0. Back to Main Menu
""")

        choice = input("Select an option: ").strip()

        if choice == "0":
            return

        config = load_config()
        if config is None:
            return

        if choice == "1":
            list_fortigate_devices(config.get("devices", {}))
        elif choice == "2":
            edit_fortigate_device(config)
        elif choice == "3":
            update_fortigate_token(config)
        elif choice == "4":
            remove_fortigate_device(config)
        elif choice == "5":
            configure_ssh_access(config)
        elif choice == "6":
            change_ssh_password(config)
        elif choice == "7":
            remove_ssh_access(config)
        else:
            print("[ERROR] Invalid option.")



def test_fortigate_connectivity():
    """Test FortiGate HTTPS and REST API access without changing settings."""
    import json as json_module
    import ssl
    import urllib.error
    import urllib.parse
    import urllib.request

    import keyring

    print("\n========== Test FortiGate Connectivity ==========")

    config = load_config()
    if config is None:
        return

    devices = config.get("devices", {})
    name = select_fortigate_device(devices)
    if name is None:
        return

    device = devices[name]

    try:
        token = keyring.get_password("fortigate-mcp-manager", name)
    except Exception as exc:
        print(f"[ERROR] Keychain access failed: {type(exc).__name__}")
        return

    if not token:
        print("[ERROR] No API token found in the credential store.")
        return

    host = device["host"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    base_url = f"https://{host}:{device['port']}"
    vdom = device["default_vdom"]

    context = ssl.create_default_context(
        cafile=device.get("ca_cert") or None
    ) if device["verify_ssl"] else ssl._create_unverified_context()

    def request_api(endpoint, params=None):
        query = urllib.parse.urlencode(params or {})
        url = f"{base_url}{endpoint}"
        if query:
            url += "?" + query

        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json"
            },
            method="GET"
        )

        with urllib.request.urlopen(
            request,
            timeout=device["timeout"],
            context=context
        ) as response:
            return response.status, json_module.load(response)

    print(f"\nDevice: {name}")
    print(f"Management: {base_url}")
    print(f"Default VDOM: {vdom}")

    try:
        status, data = request_api("/api/v2/monitor/system/status")

        if status != 200 or not isinstance(data, dict):
            print("[ERROR] Unexpected API response.")
            return

        if data.get("status") == "error":
            print("[ERROR] FortiGate API reported an error.")
            return

        results = data.get("results", {})
        if not isinstance(results, dict):
            results = {}

        print("[OK] HTTPS connection established.")
        print("[OK] API authentication successful.")

        version = (
            results.get("version")
            or data.get("version")
            or "Not reported"
        )
        serial = (
            results.get("serial")
            or results.get("serial_number")
            or data.get("serial")
            or "Not reported"
        )

        print(f"[INFO] FortiOS version: {version}")
        print(f"[INFO] Serial number: {serial}")

    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            print(f"[ERROR] API authentication/authorization failed (HTTP {exc.code}).")
        else:
            print(f"[ERROR] FortiGate returned HTTP {exc.code}.")
        return
    except ssl.SSLError:
        print("[ERROR] TLS certificate validation failed.")
        return
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"[ERROR] Connection failed: {type(exc).__name__}")
        return
    except (ValueError, TypeError):
        print("[ERROR] FortiGate returned invalid JSON.")
        return

    try:
        status, data = request_api(
            "/api/v2/cmdb/system/interface",
            {"vdom": vdom}
        )

        if status == 200 and data.get("status") != "error":
            print(f"[OK] API read request succeeded for VDOM '{vdom}'.")
            print("[INFO] This does not independently verify VDOM scope.")
        else:
            print(f"[WARNING] VDOM '{vdom}' read request was not successful.")

    except urllib.error.HTTPError as exc:
        print(f"[WARNING] VDOM API request returned HTTP {exc.code}.")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, TypeError):
        print("[WARNING] Could not complete VDOM API check.")

    if device.get("ssh_username"):
        try:
            from ssh_setup import test_ssh

            ok, message = test_ssh(name, device)
            print(f"[OK] SSH login succeeded ({message})." if ok else f"[WARNING] {message}.")
        except ImportError:
            print("[WARNING] SSH test skipped: run the manager from the project virtualenv.")
    else:
        print("[INFO] SSH not configured (optional; needed for debug / packet capture).")

    print("\n[OK] Connectivity test completed.")



def confirm_integration_plan(actions):
    """Show proposed actions and require explicit approval."""
    print("\n" + "=" * 54)
    print("         FORTIGATE MCP INTEGRATION PLAN")
    print("=" * 54)

    for index, action in enumerate(actions, 1):
        print(f"{index}. {action}")

    print("\nSecurity and safeguards:")
    print(" - Existing MCP registrations will be preserved.")
    print(" - Configuration backups will be created before changes.")
    print(" - API tokens will not be written to AI client configs.")

    print("\nNo changes have been made.")
    print("=" * 54)

    answer = input("Apply these changes? [y/N]: ").strip().lower()

    if answer == "y":
        print("[OK] User approved the integration plan.")
        return True

    print("[INFO] Integration cancelled. No changes made.")
    return False



def integrate_ai_clients():
    """Configure AI clients individually, with explicit approval."""
    from ai_client_detection import detect_ai_clients

    names = {
        "claude": "Claude Desktop",
        "codex": "OpenAI Codex",
    }

    while True:
        result = detect_ai_clients()
        os_names = {
            "Darwin": "macOS",
            "Windows": "Windows",
            "Linux": "Linux",
        }

        print("\n========== One-Click AI Client Integration ==========")
        print("Operating system:", os_names.get(result["os"], result["os"]))
        print("\nDetected AI Clients:")

        for key, name in names.items():
            status = "[OK]" if result[key]["installed"] else "[NOT DETECTED]"
            print(f"{status} {name}")

        print("\n1. Configure Claude Desktop")
        print("2. Configure OpenAI Codex")
        print("3. Check Integration Status")
        print("0. Back")

        choice = input("\nSelect: ").strip()

        if choice == "0":
            return

        if choice == "3":
            for key, name in names.items():
                print(f"\n{name}:")
                print("  Configuration:", result[key]["config"])
                print("  Config exists:", result[key]["config_exists"])
            continue

        key = {"1": "claude", "2": "codex"}.get(choice)

        if key is None:
            print("[ERROR] Invalid selection.")
            continue

        name = names[key]
        client = result[key]

        if not client["installed"]:
            print(f"[ERROR] {name} was not detected.")
            continue

        actions = [
            f"Configure {name} with the FortiGate MCP server.",
            f"Target configuration: {client['config']}",
        ]

        if key == "codex":
            from ai_client_integration import (
                build_codex_plan,
                apply_codex_plan,
            )

            config = load_config()
            if not isinstance(config, dict):
                continue

            devices = config.get("devices", {})
            device_name = select_fortigate_device(devices)
            if device_name is None:
                continue

            try:
                plan = build_codex_plan(
                    config["mcp_location"],
                    device_name,
                )
            except Exception as exc:
                print(f"[ERROR] Cannot prepare Codex integration: {exc}")
                continue

            actions = [
                f"Add FortiGate MCP registration to {name}.",
                f"Configuration: {plan['config_path']}",
                f"FortiGate: {plan['device']}",
                f"MCP project: {plan['project']}",
                f"Executable: {plan['uv']}",
                f"Preserve {len(plan['existing_servers'])} existing MCP servers.",
            ]

            if confirm_integration_plan(actions):
                try:
                    backup = apply_codex_plan(plan)
                    print("\n[OK] Codex integration completed.")
                    print("[OK] Configuration backup:", backup)
                    print("[INFO] Restart Codex to load the new MCP server.")
                except Exception as exc:
                    print(f"[ERROR] Codex integration failed: {exc}")

        elif key == "claude":
            from claude_integration import (
                build_claude_plan,
                apply_claude_plan,
            )

            config = load_config()
            if not isinstance(config, dict):
                continue

            devices = config.get("devices", {})
            device_name = select_fortigate_device(devices)
            if device_name is None:
                continue

            try:
                plan = build_claude_plan(
                    config["mcp_location"],
                    device_name,
                )
            except Exception as exc:
                print(f"[ERROR] Cannot prepare Claude integration: {exc}")
                continue

            actions = [
                f"{plan['action']} FortiGate MCP registration in Claude Desktop.",
                f"Configuration: {plan['config_path']}",
                f"FortiGate: {plan['device']}",
                f"MCP project: {plan['project']}",
                f"Executable: {plan['uv']}",
                "Preserve all other MCP servers and Claude settings.",
                "Create a verified backup before updating.",
            ]

            if confirm_integration_plan(actions):
                try:
                    backup = apply_claude_plan(plan)
                    print("\n[OK] Claude Desktop integration completed.")
                    print("[OK] Configuration backup:", backup)
                    print("[INFO] Restart Claude Desktop to load the MCP server.")
                except Exception as exc:
                    print(f"[ERROR] Claude integration failed: {exc}")

def main():
    while True:
        print(MENU)
        choice = input("Select an option: ").strip()

        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "1":
            set_mcp_location()
        elif choice == "2":
            check_prerequisites()
        elif choice == "3":
            add_fortigate_device()
        elif choice == "4":
            manage_fortigate_devices()
        elif choice == "5":
            test_fortigate_connectivity()
        elif choice == "6":
            integrate_ai_clients()
        elif choice in {str(i) for i in range(7, 11)}:
            print(f"\nOption {choice} is not implemented yet.")
        else:
            print("\nInvalid option. Please try again.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
