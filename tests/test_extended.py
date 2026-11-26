"""Tests for redaction and the extended tools (device_info, cmdb_schema, cmdb_patch).

No FortiGate is contacted: HTTP is mocked with pytest-httpx.
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest

from fortios_client import FortiOSClient, FortiOSError
from redaction import REDACTED, is_secret_key, redact
from server import mcp
from tools.extended import plan_patch, summarize_schema, verify_patch

HOST = "https://fgt.test"


def tool(name):
    return mcp._tool_manager._tools[name].fn


class FakeCtx:
    def __init__(self, client):
        self.request_context = SimpleNamespace(lifespan_context={"client": client})

    async def error(self, msg):  # pragma: no cover - only used on generic tool errors
        pass


def url(path, **q):
    return re.compile(re.escape(f"{HOST}/api/v2/{path}") + r"(\?.*)?$")


# ── redaction ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "key",
    ["password", "psksecret", "psksecret-remote", "private-key", "api-key", "passwd", "community",
     "secret", "key", "auth-pwd", "priv-pwd", "ppk-secret", "ldap-password", "token"],
)
def test_secret_keys(key):
    assert is_secret_key(key)


@pytest.mark.parametrize(
    "key",
    ["key-type", "keylife", "keylifeseconds", "password-policy", "password-expire", "psk-type",
     "name", "srcaddr", "token-type", "admin-sport"],
)
def test_not_secret_keys(key):
    assert not is_secret_key(key)


def test_redact_nested_and_enc_values():
    data = {
        "results": [
            {"name": "to-HQ", "psksecret": "ENC abc==", "keylife": 86400,
             "remote-gw": "203.0.113.10", "comments": "ENC xyz",
             "users": [{"name": "u1", "passwd": "ENC 123"}]},
        ]
    }
    out = redact(data)
    r = out["results"][0]
    assert r["psksecret"] == REDACTED
    assert r["comments"] == REDACTED          # ENC value under a non-secret key
    assert r["users"][0]["passwd"] == REDACTED
    assert r["keylife"] == 86400 and r["remote-gw"] == "203.0.113.10" and r["name"] == "to-HQ"
    assert data["results"][0]["psksecret"] == "ENC abc=="  # original untouched


# ── client ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_client_redacts_responses_and_blocks_marker(httpx_mock):
    httpx_mock.add_response(url=url("cmdb/vpn.ipsec/phase1-interface/to-HQ"),
                            json={"http_status": 200, "results": [{"name": "to-HQ", "psksecret": "ENC a"}]})
    httpx_mock.add_response(url=url("cmdb/vpn.ipsec/phase1-interface/to-HQ"),
                            json={"http_status": 200, "results": [{"name": "to-HQ", "psksecret": "ENC a"}]})
    async with FortiOSClient(HOST, "t") as c:
        red = await c.cmdb_get("vpn.ipsec/phase1-interface/to-HQ")
        raw = await c.cmdb_get("vpn.ipsec/phase1-interface/to-HQ", raw=True)
        assert red["results"][0]["psksecret"] == REDACTED
        assert raw["results"][0]["psksecret"] == "ENC a"
        with pytest.raises(FortiOSError):
            await c.cmdb_put("vpn.ipsec/phase1-interface/to-HQ", {"psksecret": REDACTED})


# ── pure helpers ─────────────────────────────────────────────────────────


def test_plan_patch_diff_unknown_and_already_set():
    current = {"policyid": 12, "status": "enable", "srcaddr": [{"name": "all", "q_origin_key": "all"}],
               "psksecret": "ENC x"}
    p = plan_patch(current, {"status": "disable", "srcaddr": [{"name": "all"}], "stauts": "x", "psksecret": "new"})
    assert [c["field"] for c in p["changes"]] == ["status", "psksecret"]
    assert p["already_set"] == ["srcaddr"]
    assert p["unknown_fields"][0]["field"] == "stauts" and "status" in p["unknown_fields"][0]["did_you_mean"]
    secret = [c for c in p["changes"] if c["field"] == "psksecret"][0]
    assert secret["old"] == REDACTED and secret["new"] == REDACTED


def test_verify_patch_detects_unexpected_changes():
    before = {"status": "enable", "comments": "a", "schedule": "always"}
    good = {"status": "disable", "comments": "a", "schedule": "always"}
    bad = {"status": "disable", "comments": "", "schedule": "always"}
    assert verify_patch(before, good, {"status": "disable"})["verified"] is True
    v = verify_patch(before, bad, {"status": "disable"})
    assert v["verified"] is False and v["unexpected_changes"] == ["comments"]


def test_summarize_schema():
    resp = {"results": {"name": "policy", "path": "firewall", "mkey": "policyid", "children": {
        "action": {"type": "option", "options": [{"name": "accept"}, {"name": "deny"}], "default": "deny"},
        "name": {"type": "string", "size": 35},
    }}}
    s = summarize_schema(resp)
    assert s["mkey"] == "policyid" and s["field_count"] == 2
    action = [f for f in s["fields"] if f["name"] == "action"][0]
    assert action["options"] == ["accept", "deny"]
    assert summarize_schema(resp, "actoin")["did_you_mean"] == ["action"]


# ── tools end to end (mocked HTTP) ───────────────────────────────────────


@pytest.mark.asyncio
async def test_device_info(httpx_mock):
    httpx_mock.add_response(url=url("monitor/system/status"), json={
        "http_status": 200, "serial": "FGT70GTK0000", "version": "v7.6.6", "build": 3652, "vdom": "root",
        "results": {"hostname": "Forti-70G", "model": "FGT70G", "model_name": "FortiGate", "model_number": "70G"}})
    async with FortiOSClient(HOST, "t") as c:
        r = await tool("device_info")(FakeCtx(c))
    assert r["version"] == "v7.6.6" and r["model_number"] == "70G" and r["serial"] == "FGT70GTK0000"


@pytest.mark.asyncio
async def test_cmdb_schema_uses_action_schema(httpx_mock):
    httpx_mock.add_response(url=re.compile(re.escape(f"{HOST}/api/v2/cmdb/firewall/policy") + r"\?.*action=schema.*"),
                            json={"http_status": 200, "results": {"name": "policy", "children": {
                                "psksecret": {"type": "password"}}}})
    async with FortiOSClient(HOST, "t") as c:
        r = await tool("cmdb_schema")(FakeCtx(c), resource_path="firewall/policy")
    # schema is returned intact (a field definition is not a secret value)
    assert r["fields"][0] == {"name": "psksecret", "type": "password"}


@pytest.mark.asyncio
async def test_cmdb_patch_dry_run_writes_nothing(httpx_mock):
    httpx_mock.add_response(method="GET", url=url("cmdb/firewall/policy/12"),
                            json={"http_status": 200, "results": [{"policyid": 12, "status": "enable"}]})
    async with FortiOSClient(HOST, "t") as c:
        r = await tool("cmdb_patch")(FakeCtx(c), resource_path="firewall/policy/12",
                                     changes='{"status": "disable"}')
    assert r["dry_run"] is True and r["changes"][0]["field"] == "status"
    assert all(req.method == "GET" for req in httpx_mock.get_requests())


@pytest.mark.asyncio
async def test_cmdb_patch_writes_only_changed_fields_and_verifies(httpx_mock):
    before = {"policyid": 12, "status": "enable", "comments": "keep", "name": "p12"}
    after = {"policyid": 12, "status": "disable", "comments": "keep", "name": "p12"}
    httpx_mock.add_response(method="GET", url=url("cmdb/firewall/policy/12"), json={"http_status": 200, "results": [before]})
    httpx_mock.add_response(method="PUT", url=url("cmdb/firewall/policy/12"), json={"http_status": 200, "status": "success"})
    httpx_mock.add_response(method="GET", url=url("cmdb/firewall/policy/12"), json={"http_status": 200, "results": [after]})
    async with FortiOSClient(HOST, "t") as c:
        r = await tool("cmdb_patch")(FakeCtx(c), resource_path="firewall/policy/12",
                                     changes='{"status": "disable", "name": "p12"}', dry_run=False)
    put = [q for q in httpx_mock.get_requests() if q.method == "PUT"][0]
    assert json.loads(put.content) == {"status": "disable"}      # unchanged "name" not sent
    assert r["verification"]["verified"] is True and r["already_set"] == ["name"]


@pytest.mark.asyncio
async def test_cmdb_patch_reports_side_effects(httpx_mock):
    before = {"policyid": 12, "status": "enable", "comments": "keep"}
    after = {"policyid": 12, "status": "disable", "comments": ""}      # device reset another field
    httpx_mock.add_response(method="GET", url=url("cmdb/firewall/policy/12"), json={"http_status": 200, "results": [before]})
    httpx_mock.add_response(method="PUT", url=url("cmdb/firewall/policy/12"), json={"http_status": 200, "status": "success"})
    httpx_mock.add_response(method="GET", url=url("cmdb/firewall/policy/12"), json={"http_status": 200, "results": [after]})
    async with FortiOSClient(HOST, "t") as c:
        r = await tool("cmdb_patch")(FakeCtx(c), resource_path="firewall/policy/12",
                                     changes='{"status": "disable"}', dry_run=False)
    assert r["verification"]["verified"] is False
    assert r["verification"]["unexpected_changes"] == ["comments"]


@pytest.mark.asyncio
async def test_cmdb_patch_rejects_unknown_fields_and_marker(httpx_mock):
    httpx_mock.add_response(method="GET", url=url("cmdb/firewall/policy/12"),
                            json={"http_status": 200, "results": [{"policyid": 12, "status": "enable"}]})
    async with FortiOSClient(HOST, "t") as c:
        r = await tool("cmdb_patch")(FakeCtx(c), resource_path="firewall/policy/12",
                                     changes='{"stauts": "disable"}', dry_run=False)
        m = await tool("cmdb_patch")(FakeCtx(c), resource_path="firewall/policy/12",
                                     changes=json.dumps({"psksecret": REDACTED}), dry_run=False)
    assert "unknown fields" in r["error"]
    assert "REDACTED" in m["error"]
    assert not [q for q in httpx_mock.get_requests() if q.method == "PUT"]


# ── read params, exists, move, clone, directory, log search ─────────────

from query_params import ParamError, parse_read_params  # noqa: E402


def test_parse_read_params_allows_reads_only():
    assert parse_read_params('{"with_meta": true, "scope": "global"}') == {"with_meta": "true", "scope": "global"}
    for bad in ('{"action": "move"}', '{"nkey": "x"}', '{"scope": "all"}', '[1]', 'nope'):
        with pytest.raises(ParamError):
            parse_read_params(bad)


@pytest.mark.asyncio
async def test_cmdb_get_and_list_pass_params(httpx_mock):
    httpx_mock.add_response(url=re.compile(r".*/cmdb/firewall/address/a1\?.*with_meta=true.*"),
                            json={"http_status": 200, "results": [{"name": "a1"}]})
    httpx_mock.add_response(url=re.compile(r".*/cmdb/firewall/address\?.*filter=name%3D%40web.*datasource=true.*"),
                            json={"http_status": 200, "results": []})
    async with FortiOSClient(HOST, "t") as c:
        g = await tool("cmdb_get")(FakeCtx(c), resource_path="firewall/address/a1", params='{"with_meta": true}')
        lst = await tool("cmdb_list")(FakeCtx(c), resource_path="firewall/address", filters="name=@web",
                                      params='{"datasource": true}')
        bad = await tool("cmdb_get")(FakeCtx(c), resource_path="firewall/address/a1", params='{"action": "move"}')
    assert g["results"][0]["name"] == "a1" and lst["results"] == []
    assert "action must be one of" in bad["error"]


@pytest.mark.asyncio
async def test_cmdb_exists(httpx_mock):
    httpx_mock.add_response(url=url("cmdb/firewall/address/yes"), json={"http_status": 200, "results": [{"name": "yes"}]})
    httpx_mock.add_response(url=url("cmdb/firewall/address/no"), status_code=404, json={"http_status": 404, "status": "error"})
    async with FortiOSClient(HOST, "t") as c:
        assert (await tool("cmdb_exists")(FakeCtx(c), resource_path="firewall/address/yes"))["exists"] is True
        assert (await tool("cmdb_exists")(FakeCtx(c), resource_path="firewall/address/no"))["exists"] is False


def _schema_and_order(httpx_mock, orders):
    httpx_mock.add_response(url=re.compile(r".*/cmdb/firewall/policy\?.*action=schema.*"),
                            json={"http_status": 200, "results": {"mkey": "policyid", "children": {}}}, is_reusable=True)
    for o in orders:
        httpx_mock.add_response(method="GET", url=re.compile(r".*/cmdb/firewall/policy\?.*format=policyid.*"),
                                json={"http_status": 200, "results": [{"policyid": i} for i in o]})


@pytest.mark.asyncio
async def test_cmdb_move_dry_run_and_verify(httpx_mock):
    _schema_and_order(httpx_mock, [[1, 2, 3], [1, 2, 3], [3, 1, 2]])
    httpx_mock.add_response(method="PUT", url=re.compile(r".*/cmdb/firewall/policy/3\?.*action=move.*before=1.*"),
                            json={"http_status": 200, "status": "success"})
    async with FortiOSClient(HOST, "t") as c:
        d = await tool("cmdb_move")(FakeCtx(c), resource_path="firewall/policy/3", position="before", neighbor_key="1")
        w = await tool("cmdb_move")(FakeCtx(c), resource_path="firewall/policy/3", position="before", neighbor_key="1",
                                    dry_run=False)
    assert d["dry_run"] is True and d["current_index"] == 2
    assert w["verification"] == {"verified": True, "new_index": 0, "neighbor_index": 1}


@pytest.mark.asyncio
async def test_cmdb_move_rejects_bad_input(httpx_mock):
    _schema_and_order(httpx_mock, [[1, 2]])
    async with FortiOSClient(HOST, "t") as c:
        r = await tool("cmdb_move")(FakeCtx(c), resource_path="firewall/policy/9", position="before", neighbor_key="1")
        p = await tool("cmdb_move")(FakeCtx(c), resource_path="firewall/policy/1", position="top", neighbor_key="2")
    assert "not found" in r["error"] and "position" in p["error"]


@pytest.mark.asyncio
async def test_cmdb_clone(httpx_mock):
    httpx_mock.add_response(method="GET", url=url("cmdb/firewall/address/web"), json={"http_status": 200, "results": [{"name": "web"}]},
                            is_reusable=True)
    httpx_mock.add_response(method="GET", url=url("cmdb/firewall/address/web2"), status_code=404, json={"http_status": 404})
    httpx_mock.add_response(method="GET", url=url("cmdb/firewall/address/web2"), status_code=404, json={"http_status": 404})
    httpx_mock.add_response(method="POST", url=re.compile(r".*/cmdb/firewall/address/web\?.*action=clone.*nkey=web2.*"),
                            json={"http_status": 200, "status": "success"})
    httpx_mock.add_response(method="GET", url=url("cmdb/firewall/address/web2"), json={"http_status": 200, "results": [{"name": "web2"}]})
    async with FortiOSClient(HOST, "t") as c:
        d = await tool("cmdb_clone")(FakeCtx(c), resource_path="firewall/address/web", new_key="web2")
        w = await tool("cmdb_clone")(FakeCtx(c), resource_path="firewall/address/web", new_key="web2", dry_run=False)
    assert d["dry_run"] is True and "error" not in d
    assert w["verification"]["verified"] is True


@pytest.mark.asyncio
async def test_api_directory_and_log_search(httpx_mock):
    httpx_mock.add_response(url=url("monitor/"), json=[{"name": "system", "path": "system"}])
    httpx_mock.add_response(method="POST", url=url("log/disk/traffic/forward"),
                            json={"http_status": 200, "results": [{"srcip": "10.0.0.1", "psksecret": "ENC x"}]})
    async with FortiOSClient(HOST, "t") as c:
        d = await tool("api_directory")(FakeCtx(c), section="monitor")
        bad = await tool("api_directory")(FakeCtx(c), section="admin")
        s = await tool("log_search")(FakeCtx(c), log_path="disk/traffic/forward", body='{"rows": 10}')
    assert d["directory"][0]["name"] == "system"
    assert "unknown API section" in bad["error"]
    assert s["results"][0]["psksecret"] == REDACTED
