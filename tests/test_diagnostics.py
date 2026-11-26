"""Tests for the SSH diagnostics tools: CPU gates, filters, limits and guaranteed cleanup.

No FortiGate is contacted: CPU comes from a fake REST client, CLI from a fake SSH runner.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from redaction import redact_text
from server import mcp
from ssh_runner import FortiSSH, SessionResult, SSHNotConfigured
from tools.diagnostics import capture_limit, parse_cpu


def tool(name):
    return mcp._tool_manager._tools[name].fn


class FakeClient:
    vdom = "root"

    def __init__(self, cpu, mode="no-vdom", vdoms=("root",)):
        self.cpu, self.mode, self.vdoms = cpu, mode, list(vdoms)

    async def cmdb_get(self, path, params=None, vdom=None, raw=False):
        if path == "system/global":
            return {"results": {"vdom-mode": self.mode}}
        assert path == "system/vdom"
        return {"results": [{"name": v} for v in self.vdoms]}

    async def monitor_get(self, path, params=None, vdom=None):
        assert path == "system/resource/usage"
        if self.cpu is None:
            return {"results": {}}
        return {"results": {"cpu": [{"current": self.cpu}]}}


class FakeSSH:
    configured = True

    def __init__(self, output="", fail=False):
        self.calls, self.output, self.fail = [], output, fail

    async def run_session(self, setup, collect_seconds, cleanup, stop=None, interrupt_first=False, max_chars=200_000):
        self.calls.append({"setup": setup, "seconds": collect_seconds, "cleanup": cleanup,
                           "interrupt_first": interrupt_first})
        return SessionResult(output=self.output, cleanup_ok=True, commands=setup + cleanup)


def ctx(cpu=10, ssh=None, mode="no-vdom", vdoms=("root",)):
    return SimpleNamespace(request_context=SimpleNamespace(
        lifespan_context={"client": FakeClient(cpu, mode, vdoms), "ssh": ssh or FakeSSH()}))


MULTI = {"mode": "multi-vdom", "vdoms": ("root", "Mina-VDOM1")}


# ── limits ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("cpu,limit", [(0, 100), (49.9, 100), (50, 10), (89, 10), (90, None), (99, None)])
def test_capture_limit(cpu, limit):
    assert capture_limit(cpu) == limit


def test_parse_cpu_shapes():
    assert parse_cpu({"results": {"cpu": [{"current": 7}]}}) == 7
    assert parse_cpu({"results": {"cpu": 12}}) == 12
    assert parse_cpu({"results": {}}) is None


# ── debug ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_debug_refused_at_high_cpu():
    ssh = FakeSSH()
    r = await tool("debug_flow")(ctx(95, ssh), addr="10.0.0.5")
    assert r["refused"] and "95%" in r["warning"] and not ssh.calls


@pytest.mark.asyncio
async def test_debug_refused_when_cpu_unknown():
    ssh = FakeSSH()
    r = await tool("debug_flow")(ctx(None, ssh), addr="10.0.0.5")
    assert r["refused"] and "fail closed" in r["reason"] and not ssh.calls


@pytest.mark.asyncio
async def test_flow_debug_needs_filter():
    ssh = FakeSSH()
    r = await tool("debug_flow")(ctx(10, ssh))
    assert r["refused"] and "debug all" in r["reason"] and not ssh.calls


@pytest.mark.asyncio
async def test_flow_debug_commands_and_cleanup():
    ssh = FakeSSH(output="id=65308 trace_id=1 func=print_pkt_detail msg=\"vd-root received a packet\"")
    r = await tool("debug_flow")(ctx(30, ssh), addr="10.0.0.5", dport=443, packets=500, seconds=999)
    call = ssh.calls[0]
    assert "diagnose debug flow filter addr 10.0.0.5" in call["setup"]
    assert "diagnose debug flow filter dport 443" in call["setup"]
    assert call["setup"][-1] == "diagnose debug flow trace start 100"      # capped
    assert call["seconds"] == 120                                           # capped
    assert call["cleanup"][-2:] == ["diagnose debug disable", "diagnose debug reset"]
    assert r["debug_disabled_after"] is True


@pytest.mark.asyncio
async def test_flow_debug_rejects_bad_ip():
    r = await tool("debug_flow")(ctx(10), addr="10.0.0.5; diagnose sys kill")
    assert r["refused"]


@pytest.mark.asyncio
async def test_ike_debug_needs_filter_and_clears_it():
    ssh = FakeSSH()
    assert (await tool("debug_ike")(ctx(10, ssh)))["refused"]
    await tool("debug_ike")(ctx(10, ssh, **MULTI), rem_addr4="203.0.113.10", vdom="root")
    call = ssh.calls[0]
    assert "diagnose vpn ike log filter rem-addr4 203.0.113.10" in call["setup"]
    assert call["setup"][:2] == ["config vdom", "edit root"]
    assert "diagnose debug application ike 0" in call["cleanup"]
    assert "diagnose vpn ike log filter clear" in call["cleanup"] and call["cleanup"][-1] == "end"
    # cleanup is self-contained: leaves, re-enters the VDOM, cleans up there
    assert call["cleanup"][:3] == ["end", "config vdom", "edit root"]


@pytest.mark.asyncio
async def test_application_debug_allowlist():
    ssh = FakeSSH()
    r = await tool("debug_application")(ctx(10, ssh), application="all")
    assert r["refused"] and not ssh.calls
    await tool("debug_application")(ctx(10, ssh), application="fnbamd")
    assert "diagnose debug application fnbamd -1" in ssh.calls[0]["setup"]
    assert ssh.calls[0]["cleanup"][0] == "diagnose debug application fnbamd 0"


# ── packet capture ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_capture_refused_at_90():
    ssh = FakeSSH()
    r = await tool("packet_capture")(ctx(90, ssh), interface="port1", filter="host 10.0.0.5")
    assert r["refused"] and not ssh.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("cpu,asked,used", [(70, 500, 10), (20, 500, 100), (20, 5, 5)])
async def test_capture_packet_limits(cpu, asked, used):
    ssh = FakeSSH()
    r = await tool("packet_capture")(ctx(cpu, ssh), interface="port1", filter="host 10.0.0.5", packets=asked)
    assert r["packets_used"] == used
    assert ssh.calls[0]["setup"][0] == f"diagnose sniffer packet port1 'host 10.0.0.5' 4 {used} l"
    assert ssh.calls[0]["interrupt_first"] is True and r["capture_file_created"] is False


@pytest.mark.asyncio
async def test_capture_requires_filter_and_blocks_payload_and_injection():
    ssh = FakeSSH()
    assert (await tool("packet_capture")(ctx(10, ssh), interface="any", filter=""))["refused"]
    assert (await tool("packet_capture")(ctx(10, ssh), interface="any", filter="host 1.1.1.1", verbose=6))["refused"]
    assert (await tool("packet_capture")(ctx(10, ssh), interface="any", filter="host 1.1.1.1'; exec reboot"))["refused"]
    assert not ssh.calls
    ok = await tool("packet_capture")(ctx(10, ssh), interface="any", filter="host 1.1.1.1", verbose=6,
                                      include_payload=True)
    assert ok["packets_used"] == 10


# ── read-only commands, reset, redaction ─────────────────────────────────


@pytest.mark.asyncio
async def test_diag_command_allowlist():
    ssh = FakeSSH(output="FGT # get router info routing-table all\nS* 0.0.0.0/0 [10/0] via 10.0.0.1\nFGT # ")
    ok = await tool("diag_command")(ctx(10, ssh), command="get router info routing-table all")
    assert "0.0.0.0/0" in ok["output"]
    for bad in ("config system interface", "execute reboot", "diagnose sys kill 11 1",
                "get system status; execute reboot", "diagnose debug enable", "show full-configuration"):
        assert (await tool("diag_command")(ctx(10, ssh), command=bad))["refused"], bad
    assert (await tool("diag_command")(ctx(10, ssh), command="diagnose sys session list | grep 10.0.0.5"))["output"] is not None


@pytest.mark.asyncio
async def test_debug_reset_runs_all_cleanup():
    ssh = FakeSSH()
    r = await tool("debug_reset")(ctx(99, ssh))   # works even at high CPU
    assert r["debug_disabled"] and "diagnose debug reset" in ssh.calls[0]["cleanup"]


def test_redact_text():
    out = redact_text("dec: spi=01e54b14 esp=aes key=16 914dc5d092667ed436ea7f6efb867976\n"
                      "set psksecret ENC AbC123==\npassword=hunter2")
    assert "914dc5d0" not in out and "AbC123" not in out and "hunter2" not in out
    assert "spi=01e54b14" in out


@pytest.mark.asyncio
async def test_not_configured_ssh_gives_setup_hint():
    r = await tool("debug_flow")(ctx(10, FortiSSH(host=None)), addr="10.0.0.5")
    assert "ssh_setup.py" in r["error"]


# ── runner: cleanup always runs ──────────────────────────────────────────


class _Stream:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    async def read(self, n):
        if self.chunks:
            c = self.chunks.pop(0)
            if isinstance(c, Exception):
                raise c
            return c
        await asyncio.sleep(0.05)
        return ""


class _Stdin:
    def __init__(self):
        self.written = []

    def write(self, s):
        self.written.append(s)


class _Proc:
    def __init__(self, chunks):
        self.stdout, self.stdin = _Stream(chunks), _Stdin()


class _Conn:
    def __init__(self, proc):
        self.proc, self.closed = proc, False

    async def create_process(self, **kw):
        return self.proc

    def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_runner_runs_cleanup_after_error(monkeypatch):
    proc = _Proc(["FGT # ", RuntimeError("stream broke")])
    ssh = FortiSSH("h", username="u", password="p", known_hosts="k")
    conns = [_Conn(proc), _Conn(_Proc(["FGT # "]))]

    async def fake_connect():
        return conns.pop(0)

    monkeypatch.setattr(ssh, "_connect", fake_connect)
    r = await ssh.run_session(["diagnose debug enable"], 1, ["diagnose debug disable", "diagnose debug reset"])
    assert "stream broke" in r.error and r.cleanup_ok
    assert "diagnose debug reset\n" in proc.stdin.written       # cleanup still sent


def test_runner_requires_configuration():
    with pytest.raises(SSHNotConfigured):
        FortiSSH(None)._require()


# ── multi-VDOM context ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unknown_vdom_is_refused_never_edited():
    ssh = FakeSSH()
    for name in ("Mina-VDOM9", "root2"):
        r = await tool("debug_flow")(ctx(10, ssh, **MULTI), addr="10.0.0.5", vdom=name)
        assert r["refused"] and "does not exist" in r["reason"]
        r = await tool("diag_command")(ctx(10, ssh, **MULTI), command="diagnose vpn tunnel list", vdom=name)
        assert r["refused"]
    assert not ssh.calls


@pytest.mark.asyncio
async def test_multi_vdom_defaults():
    ssh = FakeSSH()
    r = await tool("debug_flow")(ctx(10, ssh, **MULTI), addr="10.0.0.5")       # vdom-scoped -> default VDOM
    assert ssh.calls[0]["setup"][:2] == ["config vdom", "edit root"] and "default VDOM" in r["note"]
    await tool("debug_application")(ctx(10, ssh, **MULTI), application="fnbamd")  # auto -> global
    assert ssh.calls[1]["setup"][0] == "config global"
    await tool("diag_command")(ctx(10, ssh, **MULTI), command="get system performance status")
    assert ssh.calls[2]["setup"][0] == "config global"
    await tool("diag_command")(ctx(10, ssh, **MULTI), command="get router info routing-table all", vdom="Mina-VDOM1")
    assert ssh.calls[3]["setup"][:2] == ["config vdom", "edit Mina-VDOM1"]


@pytest.mark.asyncio
async def test_no_vdom_mode_has_no_wrapping():
    ssh = FakeSSH()
    await tool("debug_flow")(ctx(10, ssh), addr="10.0.0.5", vdom="root")
    assert ssh.calls[0]["setup"][0] == "diagnose debug reset"


@pytest.mark.asyncio
async def test_diag_command_falls_back_to_other_context():
    class Seq(FakeSSH):
        async def run_session(self, setup, collect_seconds, cleanup, **kw):
            self.calls.append({"setup": setup})
            out = "x # diagnose sys mpstat 1 1\ncommand parse error before 'mpstat'" if len(self.calls) == 1 \
                else "x (global) # diagnose sys mpstat 1 1\nCPU0 3%"
            return SessionResult(output=out, cleanup_ok=True)
    ssh = Seq()
    r = await tool("diag_command")(ctx(10, ssh, **MULTI), command="diagnose sys mpstat 1 1")
    assert ssh.calls[1]["setup"][0] == "config global" and r["context"] == "global" and "warning" not in r


@pytest.mark.asyncio
async def test_debug_reset_covers_global_and_every_vdom():
    ssh = FakeSSH()
    r = await tool("debug_reset")(ctx(99, ssh, **MULTI))
    assert [c["context"] for c in r["contexts"]] == ["global", "vdom root", "vdom Mina-VDOM1"] and r["debug_disabled"]
