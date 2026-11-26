"""Troubleshooting tools over SSH: CPU check, read-only diagnose commands, debug and packet capture.

Hard limits enforced here (not only in the AI's instructions):
- CPU is read before every debug / capture; unreadable CPU -> refuse (fail closed).
- Debug: refused at CPU >= 95 %. Never an unfiltered "debug all": flow debug needs at least
  one filter, IKE debug needs a peer or tunnel filter, BGP debug needs a neighbor, OSPF and HA debug only
  for named categories / modules (never 'all enable'), application debug only for an allowlist.
  Every debug session ALWAYS ends with debug disable + reset (also after errors/timeouts).
- Packet capture: refused at CPU >= 90 %; max 10 packets, or 100 when CPU < 50 %. A BPF filter
  is required. Headers only unless include_payload=True. The CLI sniffer stores no capture file;
  it is stopped (Ctrl-C) at the end of every call.
- Time limits: debug <= 120 s, capture <= 60 s. Output is secret-redacted and size-limited.
CLI syntax follows the FortiOS 7.6 CLI Reference (diagnose debug flow p2926-2936,
diagnose vpn ike log filter p3679-3686, diagnose sniffer packet p3319, diagnose ip router bgp p3107-3110,
diagnose ip router ospf p3116-3119, diagnose debug application hatalk/hasync p2892). BGP set-filter syntax
and the category enable form were checked live on FortiOS 7.6.8.

Author: Ehsan Emad (CyberKnightLabs)
"""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Any

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

from fortios_client import FortiOSClient, FortiOSError
from redaction import redact_text
from ssh_runner import PROMPT, FortiSSH, SSHNotConfigured

DEBUG_CPU_MAX = 95          # debug refused at or above
CAPTURE_CPU_MAX = 90        # capture refused at or above
CAPTURE_LOW_CPU = 50        # below this the larger packet limit applies
CAPTURE_MAX_NORMAL = 10
CAPTURE_MAX_LOW_CPU = 100
DEBUG_MAX_SECONDS = 120
CAPTURE_MAX_SECONDS = 60
FLOW_TRACE_MAX = 100
MAX_OUTPUT_LINES = 2000

DEBUG_APPS = {  # application debug allowlist (ike has its own tool with a filter)
    "fnbamd": "authentication (LDAP, RADIUS, TACACS+, local, FortiToken)",
    "authd": "firewall authentication / captive portal",
    "fssod": "FSSO",
    "update": "FortiGuard updates",
    "forticldd": "FortiCloud / FortiGuard connectivity",
    "csfd": "Security Fabric",
    "fgfmd": "FortiManager connectivity",
    "dnsproxy": "DNS proxy / DNS filter",
    "wad": "proxy-based inspection, explicit proxy",
    "httpsd": "GUI / REST API access",
    "dhcps": "DHCP server",
    "dhcpc": "DHCP client",
    "sslvpn": "SSL VPN (where still supported)",
}

BGP_CATEGORIES = {  # diagnose ip router bgp <category> enable ("all" is never enabled)
    "fsm": "neighbor state machine (Idle/Connect/Active/OpenSent/Established)",
    "events": "BGP events (session up/down, notifications)",
    "updates": "UPDATE messages (prefixes received / sent)",
    "keepalives": "KEEPALIVE messages (hold timer problems)",
    "filters": "route-map / prefix-list / filter decisions",
    "dampening": "route dampening",
    "nsm": "interaction with the routing table (NSM)",
}
OSPF_CATEGORIES = {  # diagnose ip router ospf <category> enable ("all" is never enabled)
    "nfsm": "neighbor state machine (Down/Init/2-Way/ExStart/Exchange/Full)",
    "ifsm": "interface state machine (DR/BDR election)",
    "events": "OSPF events",
    "packet": "OSPF packets (hello, DD, LSR, LSU, LSAck): verbose",
    "lsa": "LSA generation and flooding",
    "route": "SPF / route calculation",
    "nsm": "interaction with the routing table (NSM)",
}
ROUTER_LEVELS = ("info", "warn", "error", "critical")
HA_MODULES = {
    "hatalk": "HA protocol: heartbeat, primary election, failover",
    "hasync": "HA synchronization: configuration and session sync",
}

CLEANUP_DEBUG = ["diagnose debug disable", "diagnose debug reset"]
CLEANUP_BGP = ["diagnose ip router bgp all disable", "diagnose ip router bgp level none",
               "diagnose ip router bgp set-filter reset"]
CLEANUP_OSPF = ["diagnose ip router ospf all disable", "diagnose ip router ospf level none"]
CLEANUP_HA = ["diagnose debug application hatalk 0", "diagnose debug application hasync 0"]
CLEANUP_FLOW = ["diagnose debug flow trace stop", "diagnose debug flow filter clear", *CLEANUP_DEBUG]
CLEANUP_IKE = ["diagnose debug application ike 0", "diagnose vpn ike log filter clear", *CLEANUP_DEBUG]

READ_ONLY_PREFIXES = (
    "get system status", "get system performance status", "get system ha status", "get system interface",
    "get system arp", "get router info ", "get router info6 ", "get hardware ", "get vpn ipsec ",
    "get firewall ", "diagnose sys session list", "diagnose sys session stat", "diagnose sys ha status",
    "diagnose sys ha checksum show", "diagnose sys ha checksum cluster",  # not "recalculate"
    "diagnose sys top-summary", "diagnose sys mpstat", "diagnose hardware deviceinfo",
    "diagnose vpn ike gateway list", "diagnose vpn tunnel list", "diagnose ip arp list", "diagnose ip route list",
    "diagnose firewall iprope list", "diagnose netlink interface list", "diagnose sys virtual-wan-link",
    "diagnose sys sdwan", "diagnose test authserver", "execute ping ", "execute traceroute ",
    "execute ping-options ", "diagnose debug info", "diagnose autoupdate versions", "diagnose sys sip-proxy",
)
FORBIDDEN_TOKENS = (";", "&&", "\n", "\r", "`", "$(")


# ── helpers ──────────────────────────────────────────────────────────────


def capture_limit(cpu: float) -> int | None:
    """Max packets allowed for this CPU value, or None when capture is refused."""
    if cpu >= CAPTURE_CPU_MAX:
        return None
    return CAPTURE_MAX_LOW_CPU if cpu < CAPTURE_LOW_CPU else CAPTURE_MAX_NORMAL


def parse_cpu(resp: dict[str, Any]) -> float | None:
    """Current CPU % from /monitor/system/resource/usage (several FortiOS response shapes)."""
    res = resp.get("results", resp)
    cpu = res.get("cpu") if isinstance(res, dict) else None
    if isinstance(cpu, list) and cpu:
        cpu = cpu[0]
    if isinstance(cpu, dict):
        for k in ("current", "cpu", "value"):
            if isinstance(cpu.get(k), (int, float)):
                return float(cpu[k])
    if isinstance(cpu, (int, float)):
        return float(cpu)
    return None


async def read_cpu(client: FortiOSClient, vdom: str | None = None) -> float | None:
    try:
        resp = await client.monitor_get("system/resource/usage", {"resource": "cpu", "interval": "1-min"}, vdom=vdom)
    except FortiOSError:
        return None
    return parse_cpu(resp)


def _ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def _name(value: str, what: str, size: int = 35) -> str:
    if not re.fullmatch(rf"[\w.\-]{{1,{size}}}", value or ""):
        raise ValueError(f"invalid {what}: {value!r}")
    return value


def _categories(values: list[str] | None, allowed: dict[str, str], default: list[str], what: str) -> list[str]:
    cats = [str(v).strip().lower() for v in (values or default)]
    if not cats:
        raise ValueError(f"at least one {what} category is required")
    if "all" in cats:
        raise ValueError(f"'all' is never enabled (no unfiltered debug); pick categories from: {', '.join(allowed)}")
    bad = [c for c in cats if c not in allowed]
    if bad:
        raise ValueError(f"unknown {what} categor{'y' if len(bad) == 1 else 'ies'} {bad}; allowed: {', '.join(allowed)}")
    return list(dict.fromkeys(cats))


def _bpf(value: str) -> str:
    v = (value or "").strip()
    if not v:
        raise ValueError("a capture filter is required (e.g. 'host 10.0.0.5 and port 443')")
    if len(v) > 200 or not re.fullmatch(r"[\w\s.:/\-()!=<>&|\[\]]+", v):
        raise ValueError("filter may contain only letters, digits, spaces and . : / - ( ) ! = < > & | [ ]")
    return v


# ── CLI context (multi-VDOM) ─────────────────────────────────────────────
# In multi-VDOM mode almost no diagnose command works at the top-level prompt; each one needs
# "config global" or "config vdom / edit <vdom>". Scopes below were tested on FortiOS 7.6.8
# (FWF-40F, multi-VDOM). Unknown commands default to the VDOM context and fall back to global
# when the CLI answers "command parse error" (read-only commands only).
GLOBAL_ONLY = ("get system status", "get system performance status", "get system ha status", "get hardware ",
               "diagnose hardware deviceinfo", "diagnose autoupdate versions", "diagnose sys top-summary",
               "diagnose sys ha checksum", "get system interface")
CONTEXT_ERROR = re.compile(r"command parse error|Unknown action", re.I)

async def vdom_info(client: FortiOSClient) -> tuple[str, list[str]]:
    """(vdom-mode, VDOM names) read over REST once per client. Mode: no-vdom, multi-vdom or split-vdom."""
    cached = getattr(client, "_vdom_info_cache", None)
    if cached is None:
        glob = await client.cmdb_get("system/global")
        res = glob.get("results", {})
        mode = (res[0] if isinstance(res, list) and res else res).get("vdom-mode", "no-vdom")
        names: list[str] = []
        if mode != "no-vdom":
            vd = await client.cmdb_get("system/vdom")
            names = [v.get("name") for v in vd.get("results", []) if v.get("name")]
        cached = (mode, names)
        client._vdom_info_cache = cached  # VDOMs rarely change; restart the server after adding one
    return cached


async def resolve_context(client: FortiOSClient, vdom: str | None, scope: str) -> dict[str, Any]:
    """Decide where commands run. scope: 'vdom' (needs a VDOM), 'global', or 'auto' (vdom if given, else global).

    Never 'edit' a VDOM that does not exist: in 'config vdom', edit <new name> would CREATE a VDOM.
    """
    try:
        mode, names = await vdom_info(client)
    except FortiOSError as exc:
        raise ValueError(f"could not read the VDOM mode over REST ({exc}); refused") from exc
    if mode == "no-vdom":
        return {"mode": mode, "context": "device (VDOMs disabled)", "enter": [], "leave": [],
                **({"note": f"VDOMs are disabled; vdom '{vdom}' ignored"} if vdom and vdom != "root" else {})}
    if vdom:
        _name(vdom, "vdom", 31)
        if vdom not in names:
            raise ValueError(f"VDOM '{vdom}' does not exist on this device (VDOMs: {', '.join(names)})")
    if scope == "global" or (scope == "auto" and not vdom):
        return {"mode": mode, "context": "global", "enter": ["config global"], "leave": ["end"]}
    target = vdom or client.vdom or "root"
    if target not in names:
        raise ValueError(f"default VDOM '{target}' not found; pass vdom= one of: {', '.join(names)}")
    out = {"mode": mode, "context": f"vdom {target}", "vdom": target,
           "enter": ["config vdom", f"edit {target}"], "leave": ["end"]}
    if not vdom:
        out["note"] = f"no vdom given; used the default VDOM '{target}' (VDOMs: {', '.join(names)})"
    return out


def _wrap(c: dict[str, Any], setup: list[str], cleanup: list[str]) -> tuple[list[str], list[str]]:
    """Setup runs inside the context. Cleanup is self-contained: it leaves whatever context the session is
    in ('end' is harmless at the top level), re-enters the context and runs the cleanup there, so it also
    works when it has to run on a fresh connection."""
    if not c["enter"]:
        return setup, cleanup
    full_cleanup = ["end", *c["enter"], *cleanup, *c["leave"]] if cleanup else c["leave"]
    return [*c["enter"], *setup], full_cleanup


def _ctx_report(c: dict[str, Any]) -> dict[str, Any]:
    return {k: c[k] for k in ("mode", "context", "note") if k in c}


def _trim(text: str) -> tuple[str, bool]:
    lines = redact_text(text).splitlines()
    return "\n".join(lines[:MAX_OUTPUT_LINES]), len(lines) > MAX_OUTPUT_LINES


def _ctx(ctx: Context) -> tuple[FortiOSClient, FortiSSH]:
    lc = ctx.request_context.lifespan_context
    return lc["client"], lc["ssh"]


async def _gate(client: FortiOSClient, vdom: str | None, limit: float, what: str) -> tuple[float | None, dict | None]:
    cpu = await read_cpu(client, vdom)
    if cpu is None:
        return None, {"refused": True, "reason": f"could not read CPU usage; {what} refused (fail closed)"}
    if cpu >= limit:
        return cpu, {"refused": True, "cpu": cpu,
                     "warning": f"CPU is {cpu:.0f}% (limit {limit}%): {what} would add load and was NOT started. "
                                "Use logs and read-only commands, or try again when CPU is lower."}
    return cpu, None


# ── tools ────────────────────────────────────────────────────────────────


def register(mcp: FastMCP) -> None:
    """Register the diagnostics tools."""

    @mcp.tool()
    async def cpu_usage(ctx: Context, vdom: Annotated[str | None, Field(default=None)] = None) -> dict[str, Any]:
        """Current CPU usage (%) and the debug / packet-capture limits that apply right now."""
        client, _ssh = _ctx(ctx)
        cpu = await read_cpu(client, vdom)
        if cpu is None:
            return {"error": "could not read CPU usage"}
        lim = capture_limit(cpu)
        return {"cpu": cpu, "debug_allowed": cpu < DEBUG_CPU_MAX,
                "capture_allowed": lim is not None, "capture_max_packets": lim}

    @mcp.tool()
    async def diag_command(
        ctx: Context,
        command: Annotated[str, Field(description="Read-only CLI command from the allowlist, e.g. "
                                                  "'get router info routing-table all', 'diagnose vpn tunnel list', "
                                                  "'diagnose sys session list | grep 10.0.0.5'.")],
        vdom: Annotated[str | None, Field(default=None, description="VDOM to run in (multi-VDOM devices).")] = None,
    ) -> dict[str, Any]:
        """Run one read-only diagnostic CLI command over SSH (allowlisted get/diagnose/execute ping commands;
        no config changes, no debug). Output is redacted and limited."""
        client, ssh = _ctx(ctx)
        cmd = " ".join(command.split())
        if any(t in command for t in FORBIDDEN_TOKENS):
            return {"refused": True, "reason": "command chaining is not allowed"}
        base = cmd.split(" | grep ")[0]
        if "|" in base or not any(base.startswith(p.strip()) for p in READ_ONLY_PREFIXES):
            return {"refused": True, "reason": "not in the read-only allowlist", "allowed_prefixes": list(READ_ONLY_PREFIXES)}
        scope = "global" if base.startswith(GLOBAL_ONLY) else "vdom"
        try:
            c = await resolve_context(client, vdom, scope)
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}

        async def run(cx):
            setup, cleanup = _wrap(cx, [cmd], [])
            return await ssh.run_session(setup, 20, cleanup,
                                         stop=lambda b: len(PROMPT.findall(b)) >= 1 and b.count("\n") > 1)

        try:
            r = await run(c)
            if c["enter"] and CONTEXT_ERROR.search(r.output.split(cmd, 1)[-1][:600]):
                # read-only command in the wrong context: try the other one once
                alt = await resolve_context(client, vdom, "global" if scope == "vdom" else "vdom")
                r2 = await run(alt)
                if not CONTEXT_ERROR.search(r2.output.split(cmd, 1)[-1][:600]):
                    r, c = r2, alt
        except SSHNotConfigured as exc:
            return {"error": str(exc)}
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}
        out, cut = _trim(r.output)
        extra = {"error": r.error} if r.error else {}
        if CONTEXT_ERROR.search(r.output.split(cmd, 1)[-1][:600]):
            extra["warning"] = "the CLI rejected this command (not available on this model/version or in this context)"
        return {**extra, **_ctx_report(c), "command": cmd, "output": out, "truncated": cut or r.truncated}

    @mcp.tool()
    async def debug_flow(
        ctx: Context,
        addr: Annotated[str | None, Field(default=None, description="IP to match as source OR destination.")] = None,
        saddr: Annotated[str | None, Field(default=None, description="Source IP.")] = None,
        daddr: Annotated[str | None, Field(default=None, description="Destination IP.")] = None,
        port: Annotated[int | None, Field(default=None, description="Port to match (source or destination).")] = None,
        dport: Annotated[int | None, Field(default=None, description="Destination port.")] = None,
        proto: Annotated[int | None, Field(default=None, description="IP protocol number (1 ICMP, 6 TCP, 17 UDP).")] = None,
        packets: Annotated[int, Field(default=20, description=f"Packets to trace (1-{FLOW_TRACE_MAX}).")] = 20,
        seconds: Annotated[int, Field(default=60, description=f"Collection time (5-{DEBUG_MAX_SECONDS} s). "
                                                               "Tell the user to generate the traffic now.")] = 60,
        vdom: Annotated[str | None, Field(default=None)] = None,
    ) -> dict[str, Any]:
        """Packet flow debug (diagnose debug flow) with at least one filter. Before calling, ask the user
        to be ready to generate the traffic during the collection time. Debug is always disabled and reset
        at the end. Refused at CPU >= 95 %."""
        client, ssh = _ctx(ctx)
        try:
            filters = []
            if addr:
                filters.append(f"diagnose debug flow filter addr {_ip(addr)}")
            if saddr:
                filters.append(f"diagnose debug flow filter saddr {_ip(saddr)}")
            if daddr:
                filters.append(f"diagnose debug flow filter daddr {_ip(daddr)}")
            for flag, val in (("port", port), ("dport", dport)):
                if val is not None:
                    if not 1 <= int(val) <= 65535:
                        raise ValueError(f"invalid {flag}")
                    filters.append(f"diagnose debug flow filter {flag} {int(val)}")
            if proto is not None:
                if not 0 <= int(proto) <= 255:
                    raise ValueError("invalid proto")
                filters.append(f"diagnose debug flow filter proto {int(proto)}")
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}
        if not filters:
            return {"refused": True, "reason": "no filter: an unfiltered flow debug ('debug all') is never allowed"}
        packets = max(1, min(int(packets), FLOW_TRACE_MAX))
        seconds = max(5, min(int(seconds), DEBUG_MAX_SECONDS))
        try:
            c = await resolve_context(client, vdom, "vdom")
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}
        cpu, refused = await _gate(client, c.get("vdom"), DEBUG_CPU_MAX, "debug")
        if refused:
            return refused
        setup = ["diagnose debug reset", "diagnose debug flow filter clear", *filters,
                 "diagnose debug flow show function-name enable", "diagnose debug flow show iprope enable",
                 "diagnose debug console timestamp enable", "diagnose debug enable",
                 f"diagnose debug flow trace start {packets}"]
        setup, cleanup = _wrap(c, setup, CLEANUP_FLOW)
        try:
            r = await ssh.run_session(setup, seconds, cleanup)
        except SSHNotConfigured as exc:
            return {"error": str(exc)}
        out, cut = _trim(r.output)
        extra = {"error": r.error} if r.error else {}
        return {**extra, **_ctx_report(c), "cpu_before": cpu, "filters": filters, "packets": packets, "seconds": seconds,
                "output": out, "truncated": cut or r.truncated,
                "debug_disabled_after": r.cleanup_ok, "cleanup_commands": cleanup}

    @mcp.tool()
    async def debug_ike(
        ctx: Context,
        rem_addr4: Annotated[str | None, Field(default=None, description="Remote peer IPv4 address.")] = None,
        tunnel_name: Annotated[str | None, Field(default=None, description="Phase 1 name.")] = None,
        seconds: Annotated[int, Field(default=60, description=f"Collection time (5-{DEBUG_MAX_SECONDS} s).")] = 60,
        vdom: Annotated[str | None, Field(default=None)] = None,
    ) -> dict[str, Any]:
        """IPsec IKE debug filtered to one peer or tunnel. Ask the user to bring the tunnel up (or send traffic)
        during the collection time. Debug is always disabled and the IKE filter cleared at the end."""
        client, ssh = _ctx(ctx)
        try:
            if rem_addr4:
                filt = f"diagnose vpn ike log filter rem-addr4 {_ip(rem_addr4)}"
            elif tunnel_name:
                filt = f"diagnose vpn ike log filter name {_name(tunnel_name, 'tunnel name')}"
            else:
                return {"refused": True, "reason": "IKE debug needs rem_addr4 or tunnel_name (no unfiltered debug)"}
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}
        seconds = max(5, min(int(seconds), DEBUG_MAX_SECONDS))
        try:
            c = await resolve_context(client, vdom, "vdom")
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}
        cpu, refused = await _gate(client, c.get("vdom"), DEBUG_CPU_MAX, "debug")
        if refused:
            return refused
        setup = ["diagnose debug reset", "diagnose vpn ike log filter clear", filt,
                 "diagnose debug console timestamp enable", "diagnose debug application ike -1",
                 "diagnose debug enable"]
        setup, cleanup = _wrap(c, setup, CLEANUP_IKE)
        try:
            r = await ssh.run_session(setup, seconds, cleanup)
        except SSHNotConfigured as exc:
            return {"error": str(exc)}
        out, cut = _trim(r.output)
        extra = {"error": r.error} if r.error else {}
        return {**extra, **_ctx_report(c), "cpu_before": cpu, "filter": filt, "seconds": seconds, "output": out,
                "truncated": cut or r.truncated, "debug_disabled_after": r.cleanup_ok, "cleanup_commands": cleanup}

    async def _router_debug(ctx: Context, proto: str, cats: list[str], level: str, seconds: int,
                            vdom: str | None, extra_setup: list[str], cleanup_cmds: list[str],
                            report: dict[str, Any]) -> dict[str, Any]:
        client, ssh = _ctx(ctx)
        if level not in ROUTER_LEVELS:
            return {"refused": True, "reason": f"level must be one of {', '.join(ROUTER_LEVELS)}"}
        seconds = max(5, min(int(seconds), DEBUG_MAX_SECONDS))
        try:
            c = await resolve_context(client, vdom, "vdom")  # routing daemons run per VDOM
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}
        cpu, refused = await _gate(client, c.get("vdom"), DEBUG_CPU_MAX, "debug")
        if refused:
            return refused
        setup = ["diagnose debug reset", *cleanup_cmds, "diagnose debug console timestamp enable", *extra_setup,
                 *[f"diagnose ip router {proto} {cat} enable" for cat in cats],
                 f"diagnose ip router {proto} level {level}", "diagnose debug enable"]
        setup, cleanup = _wrap(c, setup, [*cleanup_cmds, *CLEANUP_DEBUG])
        try:
            r = await ssh.run_session(setup, seconds, cleanup)
        except SSHNotConfigured as exc:
            return {"error": str(exc)}
        out, cut = _trim(r.output)
        extra: dict[str, Any] = {"error": r.error} if r.error else {}
        if CONTEXT_ERROR.search(r.output) or "Command fail" in r.output:
            extra["warning"] = f"the CLI rejected a 'diagnose ip router {proto}' command; check the output"
        return {**extra, **_ctx_report(c), "cpu_before": cpu, **report, "level": level, "seconds": seconds,
                "output": out, "truncated": cut or r.truncated, "debug_disabled_after": r.cleanup_ok,
                "cleanup_commands": cleanup}

    @mcp.tool()
    async def debug_bgp(
        ctx: Context,
        neighbor: Annotated[str, Field(description="BGP neighbor IP to debug (required: the debug is filtered to it).")],
        categories: Annotated[list[str] | None, Field(default=None, description="Any of: " + ", ".join(
            f"{k} ({v})" for k, v in BGP_CATEGORIES.items()) + ". Default: fsm, events.")] = None,
        level: Annotated[str, Field(default="info", description="info, warn, error or critical.")] = "info",
        seconds: Annotated[int, Field(default=60, description=f"Collection time (5-{DEBUG_MAX_SECONDS} s).")] = 60,
        vdom: Annotated[str | None, Field(default=None, description="VDOM where BGP runs.")] = None,
    ) -> dict[str, Any]:
        """BGP real-time debug filtered to ONE neighbor (diagnose ip router bgp set-filter neighbor <ip>).
        Read first: get router info bgp summary / neighbors and the event log. Ask the user to reproduce (e.g.
        wait for the flap, or clear the session themselves) during the collection time. BGP debug categories,
        level and the neighbor filter are always reset and debug disabled at the end."""
        try:
            nb = _ip(neighbor)
            cats = _categories(categories, BGP_CATEGORIES, ["fsm", "events"], "BGP")
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}
        return await _router_debug(ctx, "bgp", cats, (level or "info").lower(), seconds, vdom,
                                   [f"diagnose ip router bgp set-filter neighbor {nb}"], CLEANUP_BGP,
                                   {"neighbor": nb, "categories": cats})

    @mcp.tool()
    async def debug_ospf(
        ctx: Context,
        categories: Annotated[list[str] | None, Field(default=None, description="Any of: " + ", ".join(
            f"{k} ({v})" for k, v in OSPF_CATEGORIES.items()) + ". Default: nfsm, events.")] = None,
        level: Annotated[str, Field(default="info", description="info, warn, error or critical.")] = "info",
        seconds: Annotated[int, Field(default=60, description=f"Collection time (5-{DEBUG_MAX_SECONDS} s).")] = 60,
        vdom: Annotated[str | None, Field(default=None, description="VDOM where OSPF runs.")] = None,
    ) -> dict[str, Any]:
        """OSPF real-time debug for named categories only ('all' is refused). FortiOS has no per-neighbor OSPF
        debug filter, so pick the narrowest categories (nfsm for adjacency problems; 'packet' is verbose).
        Read first: get router info ospf neighbor / interface / database. OSPF debug categories and level are
        always reset and debug disabled at the end."""
        try:
            cats = _categories(categories, OSPF_CATEGORIES, ["nfsm", "events"], "OSPF")
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}
        return await _router_debug(ctx, "ospf", cats, (level or "info").lower(), seconds, vdom, [], CLEANUP_OSPF,
                                   {"categories": cats})

    @mcp.tool()
    async def debug_ha(
        ctx: Context,
        module: Annotated[str, Field(description="One of: " + ", ".join(f"{k} ({v})" for k, v in HA_MODULES.items()))],
        seconds: Annotated[int, Field(default=60, description=f"Collection time (5-{DEBUG_MAX_SECONDS} s).")] = 60,
    ) -> dict[str, Any]:
        """HA debug for one module (diagnose debug application hatalk|hasync -1), in the global context.
        Read first: get system ha status, diagnose sys ha checksum cluster and the HA event log. Refused on a
        standalone unit. Never trigger a failover to 'test' it. Debug is always disabled and reset at the end."""
        client, ssh = _ctx(ctx)
        mod = (module or "").strip().lower()
        if mod not in HA_MODULES:
            return {"refused": True, "reason": f"'{module}' is not an HA debug module", "allowed": HA_MODULES}
        try:
            ha = await client.cmdb_get("system/ha")
            res = ha.get("results", {})
            ha_mode = (res[0] if isinstance(res, list) and res else res).get("mode", "unknown")
        except FortiOSError:
            ha_mode = "unknown"
        if ha_mode == "standalone":
            return {"refused": True, "ha_mode": ha_mode,
                    "reason": "this unit is standalone (HA not configured): an HA debug would show nothing"}
        seconds = max(5, min(int(seconds), DEBUG_MAX_SECONDS))
        try:
            c = await resolve_context(client, None, "global")
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}
        cpu, refused = await _gate(client, None, DEBUG_CPU_MAX, "debug")
        if refused:
            return refused
        setup = ["diagnose debug reset", "diagnose debug console timestamp enable",
                 f"diagnose debug application {mod} -1", "diagnose debug enable"]
        setup, cleanup = _wrap(c, setup, [*CLEANUP_HA, *CLEANUP_DEBUG])
        try:
            r = await ssh.run_session(setup, seconds, cleanup)
        except SSHNotConfigured as exc:
            return {"error": str(exc)}
        out, cut = _trim(r.output)
        extra = {"error": r.error} if r.error else {}
        return {**extra, **_ctx_report(c), "ha_mode": ha_mode, "cpu_before": cpu, "module": mod, "seconds": seconds,
                "output": out, "truncated": cut or r.truncated, "debug_disabled_after": r.cleanup_ok,
                "cleanup_commands": cleanup}

    @mcp.tool()
    async def debug_application(
        ctx: Context,
        application: Annotated[str, Field(description="One of: " + ", ".join(f"{k} ({v})" for k, v in DEBUG_APPS.items()))],
        seconds: Annotated[int, Field(default=60, description=f"Collection time (5-{DEBUG_MAX_SECONDS} s).")] = 60,
        vdom: Annotated[str | None, Field(default=None)] = None,
    ) -> dict[str, Any]:
        """Debug one daemon from the allowlist (diagnose debug application <app> -1). Ask the user to
        reproduce the problem during the collection time. Always disabled and reset at the end."""
        client, ssh = _ctx(ctx)
        app = (application or "").strip().lower()
        if app not in DEBUG_APPS:
            return {"refused": True, "reason": f"'{application}' is not in the allowlist", "allowed": DEBUG_APPS}
        seconds = max(5, min(int(seconds), DEBUG_MAX_SECONDS))
        try:
            c = await resolve_context(client, vdom, "auto")
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}
        cpu, refused = await _gate(client, c.get("vdom"), DEBUG_CPU_MAX, "debug")
        if refused:
            return refused
        setup = ["diagnose debug reset", "diagnose debug console timestamp enable",
                 f"diagnose debug application {app} -1", "diagnose debug enable"]
        setup, cleanup = _wrap(c, setup, [f"diagnose debug application {app} 0", *CLEANUP_DEBUG])
        try:
            r = await ssh.run_session(setup, seconds, cleanup)
        except SSHNotConfigured as exc:
            return {"error": str(exc)}
        out, cut = _trim(r.output)
        extra = {"error": r.error} if r.error else {}
        if CONTEXT_ERROR.search(r.output):
            extra["warning"] = f"the CLI rejected 'diagnose debug application {app}': not available on this model/version"
        return {**extra, **_ctx_report(c), "cpu_before": cpu, "application": app, "seconds": seconds, "output": out,
                "truncated": cut or r.truncated, "debug_disabled_after": r.cleanup_ok, "cleanup_commands": cleanup}

    @mcp.tool()
    async def packet_capture(
        ctx: Context,
        interface: Annotated[str, Field(description="Interface name or 'any'.")],
        filter: Annotated[str, Field(description="BPF filter (required), e.g. 'host 10.0.0.5 and tcp port 443'.")],
        packets: Annotated[int, Field(default=10, description="Packets to capture; limited by CPU "
                                                               f"(<{CAPTURE_LOW_CPU}%: {CAPTURE_MAX_LOW_CPU}, "
                                                               f"else {CAPTURE_MAX_NORMAL}).")] = 10,
        verbose: Annotated[int, Field(default=4, description="1 headers, 4 headers + interface. "
                                                              "2/3/5/6 include payload (needs include_payload).")] = 4,
        include_payload: Annotated[bool, Field(default=False, description="Allow payload levels (user must approve).")] = False,
        seconds: Annotated[int, Field(default=30, description=f"Max capture time (5-{CAPTURE_MAX_SECONDS} s).")] = 30,
        vdom: Annotated[str | None, Field(default=None)] = None,
    ) -> dict[str, Any]:
        """CLI packet capture (diagnose sniffer packet) with a required filter. Ask the user to generate
        the traffic during the capture time. Refused at CPU >= 90 %. The sniffer is stopped at the end and
        no capture file is stored on the device."""
        client, ssh = _ctx(ctx)
        try:
            intf = "any" if interface == "any" else _name(interface, "interface", 15)
            bpf = _bpf(filter)
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}
        if verbose not in (1, 2, 3, 4, 5, 6):
            return {"refused": True, "reason": "verbose must be 1-6"}
        if verbose in (2, 3, 5, 6) and not include_payload:
            return {"refused": True, "reason": "verbose 2/3/5/6 show packet payload; set include_payload=true "
                                               "only after the user approved it"}
        try:
            c = await resolve_context(client, vdom, "auto")
        except ValueError as exc:
            return {"refused": True, "reason": str(exc)}
        cpu, refused = await _gate(client, c.get("vdom"), CAPTURE_CPU_MAX, "packet capture")
        if refused:
            return refused
        limit = capture_limit(cpu)
        count = max(1, min(int(packets), limit))
        seconds = max(5, min(int(seconds), CAPTURE_MAX_SECONDS))
        cmd = f"diagnose sniffer packet {intf} '{bpf}' {verbose} {count} l"
        setup, cleanup = _wrap(c, [cmd], [])
        try:
            r = await ssh.run_session(
                setup, seconds, cleanup, interrupt_first=True,
                stop=lambda b: "packets received by filter" in b or bool(re.search(r"\d+ packets? captured", b)))
        except SSHNotConfigured as exc:
            return {"error": str(exc)}
        out, cut = _trim(r.output)
        extra = {"error": r.error} if r.error else {}
        return {**extra, **_ctx_report(c), "cpu_before": cpu, "command": cmd, "packets_requested": packets, "packets_limit": limit,
                "packets_used": count, "seconds": seconds, "output": out, "truncated": cut or r.truncated,
                "capture_stopped": r.cleanup_ok, "capture_file_created": False}

    @mcp.tool()
    async def debug_reset(ctx: Context, vdom: Annotated[str | None, Field(default=None)] = None) -> dict[str, Any]:
        """Emergency cleanup: stop any flow trace, clear debug/IKE/BGP filters, turn off BGP/OSPF/HA debug,
        disable and reset all debug.
        Safe to run any time; call it after troubleshooting if anything may still be running."""
        client, ssh = _ctx(ctx)
        cleanup = ["diagnose debug flow trace stop", "diagnose debug flow filter clear",
                   "diagnose debug application ike 0", "diagnose vpn ike log filter clear",
                   *CLEANUP_BGP, *CLEANUP_OSPF, *CLEANUP_HA, *CLEANUP_DEBUG]
        # routing lines fail harmlessly in the global context, HA lines in a VDOM context
        try:
            mode, names = await vdom_info(client)
        except FortiOSError:
            mode, names = "unknown", []
        if mode == "no-vdom":
            contexts = [{"context": "device", "enter": [], "leave": []}]
        elif names:
            # flow/IKE filters are per VDOM: clear them in every VDOM, plus global
            only = [vdom] if vdom and vdom in names else names
            contexts = [{"context": "global", "enter": ["config global"], "leave": ["end"]}] + [
                {"context": f"vdom {v}", "enter": ["config vdom", f"edit {v}"], "leave": ["end"]} for v in only]
        else:
            return {"debug_disabled": False, "error": "could not read the VDOM list over REST; run debug_reset again "
                                                     "or run 'diagnose debug disable' + 'diagnose debug reset' manually"}
        results, ok_all = [], True
        try:
            for cx in contexts:
                setup, cl = _wrap(cx, [], cleanup)
                r = await ssh.run_session(setup, 0.5, cl, interrupt_first=True)
                results.append({"context": cx["context"], "ok": r.cleanup_ok, **({"error": r.error} if r.error else {})})
                ok_all = ok_all and r.cleanup_ok
        except SSHNotConfigured as exc:
            return {"error": str(exc)}
        return {"debug_disabled": ok_all, "mode": mode, "contexts": results, "commands": cleanup}
