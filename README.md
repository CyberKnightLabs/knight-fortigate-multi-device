# Knight FortiGate Multi-Device MCP

Manage FortiGate firewalls from an MCP-compatible AI client, with a terminal wizard for local device enrollment, operating-system credential storage, read-only connectivity checks, and client integration.

## Author and maintainer

**[Ehsan Emad](https://www.linkedin.com/in/ehsanemad/)** — CyberKnightLabs, creator of Networking With Ehsan and TechLoungeCast.

- [Networking With Ehsan](https://www.networkingwithehsan.com/)
- [Cisco Knight Multi-Device](https://github.com/CyberKnightLabs/cisco-knight-multi-dev)
- [VMware Knight MCP](https://github.com/CyberKnightLabs/vmware-knight-mcp)

Knight adds device enrollment, credential-manager integration and AI client setup to an MIT-licensed FortiOS API server. Required upstream copyright attribution is retained in [LICENSE](LICENSE).

## Contents

- [Purpose and architecture](#purpose-and-architecture)
- [Requirements](#requirements)
- [Install and verify prerequisites](#install-and-verify-prerequisites)
- [Prepare FortiGate API access](#prepare-fortigate-api-access)
- [Start the wizard](#start-the-wizard)
- [Every wizard menu](#every-wizard-menu)
- [Multiple devices](#multiple-devices)
- [Manual client configuration](#manual-client-configuration)
- [Tools and functions](#tools-and-functions)
- [Troubleshooting](#troubleshooting)
- [Development and validation](#development-and-validation)

## Purpose and architecture

The wizard replaces routine hand editing of connection settings. It collects a device nickname, management address, HTTPS port, VDOM, TLS preferences, timeout and hidden API token. Device metadata is saved locally; the token is stored through Python `keyring`. Client registrations contain a device selector rather than the token.

The MCP server exposes typed tools for common operations and generic API tools for other FortiOS resources. Available operations depend on firmware, platform, API permissions and VDOM scope. The source targets FortiOS 7.6.x; the existing local deployment was tested against 7.6.6. Generic API access does not guarantee that every endpoint works on every model.

**Multi-device model:** the wizard holds an inventory of devices. Each client registration starts a separate MCP process selected by `FORTIGATE_DEVICE`. This release does not switch devices inside a running process or add a `device` argument to every tool. Separate registrations let several FortiGates coexist in the same client.

The wizard enrolls local metadata and credentials; it does not provision firewall settings. Option 5 sends HTTPS GET requests. MCP tools include write and delete operations: use a read-only FortiGate API profile when you require enforced read-only access. Natural-language instructions alone do not enforce permissions.

## Requirements

| Requirement | Purpose |
|---|---|
| Python 3.11 or newer | Runs the wizard and MCP server; includes `tomllib` |
| Git | Clone and update the source |
| `uv` | Dependency installation and the wizard-generated client launcher |
| An unlocked OS credential backend | Stores tokens through `keyring`; macOS Keychain, Windows credential storage, or a configured Linux backend |
| FortiGate HTTPS management access | Network route, DNS, management HTTPS port and trusted-source access |
| FortiGate REST API administrator and token | Authenticates API calls with the profile and VDOM scope you assign |
| An MCP client | Uses the tools; automatic integrations are provided for Codex and Claude Desktop |
| Internet during installation | Downloads Python dependencies and the repository |

A headless Linux machine may need a Secret Service backend and an unlocked user session. A missing, locked or plaintext-only keyring is not equivalent to secure OS credential storage. Use `keyring diagnose` to inspect the configured backend.

## Install and verify prerequisites

### macOS / Linux

Check what is installed:

```bash
python3 --version
python3 -c "import sys; assert sys.version_info >= (3,11), 'Python 3.11+ required'; print('Python version OK')"
git --version
uv --version
command -v python3
command -v git
command -v uv
```

If `uv` is missing and Python/pip are available:

```bash
python3 -m pip install --user uv
```

If your Python installation blocks user package installation, install `uv` using your system package manager. On a Homebrew-managed Mac, for example:

```bash
brew install python uv git
```

Open a new terminal if PATH changes. Clone and install:

```bash
git clone https://github.com/CyberKnightLabs/knight-fortigate-multi-device.git
cd knight-fortigate-multi-device
uv sync --locked
uv run python -c "import mcp, httpx, pydantic, dotenv, keyring; print('Dependency imports OK')"
uv run python -m keyring diagnose
```

### Windows PowerShell

```powershell
py -3 --version
py -3 -c "import sys; assert sys.version_info >= (3,11); print('Python version OK')"
git --version
uv --version
Get-Command py,git,uv
```

Install Python 3.11+ and Git if missing. With a working Python installation, install `uv` using:

```powershell
py -3 -m pip install --user uv
```

Reopen PowerShell if required, then:

```powershell
git clone https://github.com/CyberKnightLabs/knight-fortigate-multi-device.git
cd knight-fortigate-multi-device
uv sync --locked
uv run python -c "import mcp, httpx, pydantic, dotenv, keyring; print('Dependency imports OK')"
uv run python -m keyring diagnose
```

Windows and Linux code paths are provided; this publication was validated locally on macOS, not end-to-end on those operating systems.

## Prepare FortiGate API access

Before enrolling a device, collect its management IP or DNS name, HTTPS port, default VDOM and REST API token. Create the API administrator through your FortiOS administration interface, assign a suitable access profile and VDOM access, and restrict trusted source addresses to the MCP host. Exact controls vary by firmware and administrator permissions.

For inventory and troubleshooting only, assign a read-only profile with the required resource access. A broad administrative token enables configuration-changing MCP tools. The token is displayed when created; save it securely and paste it only into the wizard's hidden terminal prompt. Do not paste it into chat, a GitHub issue or screenshots.

Allow the MCP host to reach the management HTTPS service. Use a trusted certificate or provide a PEM CA certificate path in the wizard. Keep TLS verification enabled for normal use. Disabling it skips server identity verification.

A TCP check can establish reachability without a token:

```bash
# Replace with your device and actual HTTPS port.
uv run python -c "import socket; s=socket.create_connection(('192.0.2.10',443),5); s.close(); print('TCP reachable')"
```

This does not test API authorization; option 5 does that after enrollment.

## Start the wizard

From the cloned directory on any supported platform:

```bash
uv run python manager.py
```

Alternatively, after dependency synchronization:

```bash
uv run knight-fortigate-wizard
```

Run it in your local terminal, under the same OS user who will run the AI client so both can access the same credential store. The wizard is interactive and must not be configured as the MCP stdio server command.

Recommended first-time sequence:

1. **1 — Set / Edit MCP Location:** enter the absolute path of this cloned repository.
2. **2 — Check & Install Prerequisites:** verify tools and synchronize dependencies.
3. **3 — Add FortiGate Device:** enroll one or more firewalls.
4. **5 — Test FortiGate Connectivity:** select a device and verify API access.
5. **6 — One-Click AI Client Integration:** select a client and device, inspect the plan and approve the local configuration update.
6. Fully quit and reopen the AI client, then start a new chat and request a read-only system-status or interface query.

## Every wizard menu

| Option | Function | Effect |
|---|---|---|
| 1 | Set / Edit MCP Location | Validates `server.py` and `pyproject.toml`, then saves the project path |
| 2 | Check & Install Prerequisites | Checks Python, Git and uv; can offer to install uv; runs `uv sync` in the selected project |
| 3 | Add FortiGate Device | Collects metadata and hidden token; saves token in keyring and metadata in local JSON |
| 4 | Manage FortiGate Devices | Opens the list, edit, token replacement and removal submenu |
| 5 | Test FortiGate Connectivity | Reads system status and interfaces through HTTPS GET; prints authentication and VDOM-read results |
| 6 | One-Click AI Client Integration | Detects supported clients and prepares an approved, backed-up configuration change |
| 7 | Verify Installation & Diagnostics | Reserved; currently prints “not implemented yet”; use the checks in this guide |
| 8 | Update MCP Server | Reserved; currently unimplemented; use the manual update steps below |
| 9 | Backup / Restore Configuration | Reserved; currently unimplemented; see backup notes below |
| 10 | Uninstall MCP Integration | Reserved; currently unimplemented; use manual removal below |
| 0 | Exit | Closes the wizard |

### Option 1: project location

Enter the repository folder itself, not the path to a Python file or virtual environment. It must already exist and contain `server.py` and `pyproject.toml`. The saved path is used by prerequisite synchronization and generated client launch commands. Moving the repository later requires updating the location and client registration.

### Option 2: prerequisites

Python must be 3.11+ and Git must be available. If uv is absent, the wizard offers `python -m pip install --user uv`, using its current Python interpreter. It then runs `uv sync --directory <project>`. This can download dependencies and create or update `.venv`. A success message indicates dependency synchronization completed, not that a FortiGate connection has been tested.

### Option 3: enrollment prompts

| Prompt | Input and behavior |
|---|---|
| Device name | Unique 1–64 character nickname: letters, numbers, underscores or hyphens; must start with a letter or digit |
| Management IP / FQDN | Host only, without `https://`, a path or embedded credentials |
| HTTPS port | 1–65535; default 443 |
| API token | Required, hidden terminal input; stored through keyring |
| Default VDOM | Default `root`; 1–63 letters, numbers, underscores, dots or hyphens |
| Verify SSL certificates | Default yes; choose no only if you accept skipping certificate verification |
| Custom CA path | Optional existing certificate file, offered when verification is enabled |
| Timeout | 1–300 seconds; default 30 |

Enrollment does **not** test API connectivity. Run option 5 afterwards. Repeat option 3 for additional devices; duplicate names are rejected.

### Option 4: management submenu

| Submenu | Function |
|---|---|
| 1 — List Registered Devices | Shows nickname, host, port, VDOM, verification setting, CA path and timeout; does not display tokens |
| 2 — Edit Device Settings | Select a device; Enter retains each current value; `-` clears a custom CA path; saves changed metadata |
| 3 — Update API Token | Select a device and enter a replacement hidden token; updates keyring |
| 4 — Remove Device | Select a device and type `DELETE`; removes its local metadata and keyring token |
| 0 — Back | Returns to the main menu |

Removal does not revoke the API token on the firewall and does not delete a client registration. Device renaming is not supported directly; enroll the desired new nickname and retire the old entry.

### Option 5: read-only connection test

Select a registered nickname. The wizard loads its token from keyring, creates an HTTPS connection with the selected certificate settings and issues:

```text
GET /api/v2/monitor/system/status
GET /api/v2/cmdb/system/interface?vdom=<default_vdom>
```

It reports firmware and serial information returned by the device, authentication failures and interface-read success or failure. A successful interface read is not an independent proof of VDOM isolation. Review warning lines even when the final message says the test completed. Test output can contain identifying device information; redact it before sharing.

### Option 6: client integration submenu

| Submenu | Function |
|---|---|
| 1 — Configure Claude Desktop | Select an enrolled device, inspect the generated plan and approve writing its registration |
| 2 — Configure OpenAI Codex | Select an enrolled device, inspect the plan and approve adding its registration |
| 3 — Check Integration Status | Displays detected configuration paths and whether files exist; does not establish an MCP session |
| 0 — Back | Returns to the main menu |

Each registration is named `fortigate-<device-name>`. Repeat for each device/client pair. The plan shows the client config path, selected device, project location and resolved uv executable. Enter `y` to apply. Configuration backups are created and checked before writing. Tokens are not added to client configuration.

The integration requires an existing, valid client configuration file. Open and initialize the client first. Automatic detection is heuristic: alternate installations and Store-packaged apps may require manual configuration. Existing unrelated MCP registrations are preserved.

Claude can update the same named registration. Codex currently refuses to overwrite an existing registration; remove that specific entry manually after making a backup, then rerun option 6. Older `fortigate` entries are preserved, so remove a redundant old registration yourself if it connects to the same device.

### Reserved options: diagnostics, update, backup and uninstall

Options 7–10 are visible placeholders, not implemented workflows. Use these procedures instead:

- **Diagnostics:** run the prerequisite commands, keyring diagnosis, option 5 and client-side tool discovery.
- **Update:** commit or save local edits, then run `git pull --ff-only` and `uv sync --locked` from the repository. Restart MCP clients afterwards. This is intended for an installed Git checkout, not an untracked source archive.
- **Backup:** securely copy the manager JSON and relevant client configuration. The JSON contains device addresses but not tokens. Keyring credentials require their own OS-supported backup or token re-enrollment; copying JSON alone cannot restore them. Integration backups can contain other clients' secrets, so keep them private.
- **Uninstall integration:** back up the client config, remove only the selected `fortigate-<device-name>` entry and restart the client. Option 4 can separately remove local enrollment and its token. Revoke the token through FortiGate administration if it is no longer needed.

## Multiple devices

Example nicknames `LAB-EDGE` and `BRANCH-EDGE` produce two registrations, `fortigate-LAB-EDGE` and `fortigate-BRANCH-EDGE`. Each has its own process, credentials, VDOM and TLS settings. Always identify the intended firewall in your AI request and review which server supplies the chosen tool.

```text
Using fortigate-LAB-EDGE, retrieve system status and interface names/IP addresses.
This is read-only. Do not change configuration.
```

The inventory path is currently fixed for compatibility:

```text
~/.config/fortigate-mcp-manager/config.json
```

This applies on macOS, Linux and Windows (where `~` is the current user's home). Tokens use keyring service `fortigate-mcp-manager`, keyed by the exact device nickname. POSIX metadata files are written with restricted permissions; Windows relies on the current user's filesystem protections. Run one wizard instance at a time.

## Manual client configuration

Use your absolute uv executable path (`command -v uv` on macOS/Linux, `Get-Command uv` on PowerShell), repository path and enrolled device nickname. The runtime entry point is `server.py`, not `manager.py`.

Claude Desktop example; merge into existing settings:

```json
{
  "mcpServers": {
    "fortigate-LAB-EDGE": {
      "command": "/absolute/path/to/uv",
      "args": ["run", "--directory", "/absolute/path/to/knight-fortigate-multi-device", "python", "server.py"],
      "env": {"FORTIGATE_DEVICE": "LAB-EDGE"}
    }
  }
}
```

Codex TOML example; use a distinct table name for each device:

```toml
[mcp_servers."fortigate-LAB-EDGE"]
command = "/absolute/path/to/uv"
args = ["run", "--directory", "/absolute/path/to/knight-fortigate-multi-device", "python", "server.py"]

[mcp_servers."fortigate-LAB-EDGE".env]
FORTIGATE_DEVICE = "LAB-EDGE"
```

Use forward slashes in Windows JSON/TOML paths or escape backslashes correctly. The wizard resolves executable paths automatically when detection succeeds.

Detected config locations:

| Client / OS | Default path |
|---|---|
| Claude / macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude / Windows | `%APPDATA%/Claude/claude_desktop_config.json` |
| Claude / Linux | `~/.config/Claude/claude_desktop_config.json` (client availability varies) |
| Codex | `$CODEX_HOME/config.toml`, or `~/.codex/config.toml` when unset |

### Environment-only compatibility mode

Without `FORTIGATE_DEVICE`, the server reads `FORTIOS_HOST`, `FORTIOS_API_TOKEN`, `FORTIOS_VDOM`, `FORTIOS_VERIFY_SSL` and `FORTIOS_TIMEOUT` from its environment or `.env`. See [.env.example](.env.example). The compatibility TLS default is false; explicitly enable verification for normal use. Managed mode takes precedence when `FORTIGATE_DEVICE` is set. Keep `.env` private and untracked.

### HTTP transport

The default is local stdio. An optional HTTP server can be started with:

```bash
FORTIGATE_DEVICE=LAB-EDGE MCP_TRANSPORT=streamable-http MCP_PORT=8000 uv run python server.py
```

This shell syntax is for macOS/Linux; in PowerShell set the same values with `$env:NAME='value'` before launching. The default bind address is `127.0.0.1`, endpoint `/mcp`. The project does not supply an authenticated public HTTP gateway; keep the listener local unless you provide appropriate external access controls.

## Tools and functions

See [the generated tool reference](docs/TOOLS.md) for every registered function and its source docstring.

| Module | Purpose |
|---|---|
| `generic` | CMDB list/get/create/update/delete; monitor reads/actions; logs; service calls |
| `system` | Interfaces, DNS, NTP, administrators, DHCP, certificates, VDOMs and system status |
| `firewall` | Policies, addresses, groups, services, VIPs, IP pools, schedules and sessions |
| `vpn` | IPsec and SSL VPN configuration, tunnel monitoring/control and certificates |
| `router` | Static routes, OSPF, BGP, RIP, prefix lists, route maps and SD-WAN |
| `user` | Local users, groups, RADIUS, LDAP, TACACS+, SAML and sessions |
| `monitor` | ARP, FortiView, licensing, endpoint and switch-controller monitoring |
| `log` | Traffic/event/security log retrieval and logging configuration |
| `security` | IPS, antivirus, web filtering, DLP, WAF, ZTNA and other security profiles |
| `wireless` | AP profiles, registered APs, SSIDs, Hotspot 2.0 and wireless clients |

Read-only starting requests:

```text
Get system status from the selected FortiGate.
List all interfaces with their configured IP addresses.
Show the current static routing configuration.
List firewall policies without changing them.
```

`get`, `list` and monitoring reads generally retrieve data; create, update, delete, action and service operations may change state. Inspect the individual function and its HTTP method. Use the firewall API account's permissions to enforce access boundaries.

## Troubleshooting

| Symptom | Check / resolution |
|---|---|
| Python or uv not found | Run version and PATH checks; reopen terminal after installation |
| Imports fail | Run `uv sync --locked` inside this repository; launch through `uv run` |
| Keyring exception / missing backend | Run `uv run python -m keyring diagnose`; unlock/configure a supported OS backend under the same user |
| No token found | Check exact nickname and OS user; replace token through option 4 → 3 |
| HTTP 401 / 403 | Token validity, admin access profile, trusted hosts and VDOM permissions |
| TLS validation error | Certificate identity, trust chain and custom CA path; prefer fixing trust |
| Timeout / connection refused | Management IP, DNS, HTTPS port, routing, firewall access and source restrictions |
| Option 6 cannot find client | Initialize the client and its config; use manual setup for nonstandard paths |
| Codex registration already exists | Back up config, remove only the same named entry, rerun integration |
| MCP tools missing after setup | Fully restart client and open a new chat; inspect client MCP diagnostics |
| Wrong device responds | Verify registration's `FORTIGATE_DEVICE` and selected tool server |
| Device removed but client still starts it | Remove its client registration as well |
| Option 7–10 does nothing | These are explicit placeholders; follow manual procedures above |

Do not attach tokens, `.env`, inventory JSON, keyring exports, device response dumps or private client config to issues. Use placeholder addresses such as `192.0.2.10` in shared examples.

## Development and validation

```bash
uv sync --locked
uv run pytest -q
uv run python -m compileall -q server.py manager.py manager_credentials.py tools
```

Tests use temporary client configs and mock network/credential operations. They must not enroll real devices or modify firewall configuration. Keep live API writes outside automated checks.

The publication combines the locally working API server and manager. Hardware-specific endpoint coverage and Windows/Linux end-to-end operation require additional validation. Current limitations include one selected device per MCP process, Codex add-only integration, heuristic client detection and reserved menu options 7–10.

MIT licensed; see [LICENSE](LICENSE). This project is independent of Fortinet and is not endorsed by Fortinet.
