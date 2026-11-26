"""Extended tools: live device identity, CMDB schema and safe partial updates.

- ``device_info``  — real model, serial, FortiOS version and build from the device
  (do not rely on the server's static instructions text for the version).
- ``cmdb_schema``  — the field schema of any CMDB endpoint as the device itself
  reports it (``?action=schema``), so field names/types/options match the exact
  model and FortiOS version.
- ``cmdb_patch``   — change only the given fields of one object: read the current
  object, show the diff (dry run, default), and on ``dry_run=false`` write only the
  changed fields and read back to verify that nothing else changed.
- ``cmdb_exists``  — true/false for one object.
- ``cmdb_move``    — reorder any ordered table (policies, local-in, policy routes, SD-WAN rules); dry run, verify.
- ``cmdb_clone``   — copy an object to a new key; dry run, verify.
- ``api_directory``— ask the device which endpoints exist under a section/path.
- ``log_search``   — POST to a log endpoint that takes a request body.

All outputs are redacted (see ``redaction.py``). Query options and actions follow the FortiOS
REST API (FNDN); support can differ by FortiOS version, so verify on the device.

Author: Ehsan Emad (CyberKnightLabs)
"""

from __future__ import annotations

import difflib
import json
from typing import Annotated, Any

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

from fortios_client import FortiOSClient, FortiOSError
from redaction import REDACTED, contains_redaction_marker, is_secret_key, redact

_VDOM_FIELD = Field(
    default=None,
    description="Target VDOM name. Defaults to the server default VDOM.",
)


def _first_result(resp: dict[str, Any]) -> dict[str, Any] | None:
    res = resp.get("results")
    if isinstance(res, list):
        return res[0] if res else None
    if isinstance(res, dict):
        return res
    return None


def _normalize(value: Any) -> Any:
    """Make device values comparable with requested values.

    FortiOS adds ``q_*`` helper keys to table entries and returns numbers as ints.
    """
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items() if not str(k).startswith("q_")}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        return value.strip()
    return value


def _same(a: Any, b: Any) -> bool:
    return _normalize(a) == _normalize(b)


def _shown(field: str, value: Any) -> Any:
    return REDACTED if is_secret_key(field) and value not in (None, "", [], {}) else redact(value)


def summarize_schema(resp: dict[str, Any], field: str | None = None) -> dict[str, Any]:
    """Reduce a FortiOS ``?action=schema`` response to what is needed to build config."""
    res = resp.get("results") or {}
    children = res.get("children") or {}
    if field:
        if field not in children:
            close = difflib.get_close_matches(field, list(children), n=5)
            return {"error": f"field '{field}' not in schema", "did_you_mean": close}
        return {"path": res.get("path"), "name": res.get("name"), "field": field, "schema": children[field]}

    fields = []
    for name, spec in children.items():
        item: dict[str, Any] = {"name": name, "type": spec.get("type")}
        for k in ("help", "size", "min-value", "max-value", "default", "multiple_values", "category"):
            if k in spec:
                item[k] = spec[k]
        if spec.get("options"):
            item["options"] = [o.get("name") for o in spec["options"] if isinstance(o, dict)]
        if spec.get("children"):
            item["children"] = sorted(spec["children"])
        fields.append(item)
    return {
        "path": res.get("path"),
        "name": res.get("name"),
        "help": res.get("help"),
        "category": res.get("category"),
        "mkey": res.get("mkey"),
        "mkey_type": res.get("mkey_type"),
        "field_count": len(fields),
        "fields": fields,
    }


def plan_patch(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Compare requested changes with the current object."""
    unknown = [k for k in changes if k not in current]
    diff, unchanged = [], []
    for k, v in changes.items():
        if k in unknown:
            continue
        if _same(current.get(k), v):
            unchanged.append(k)
        else:
            diff.append({"field": k, "old": _shown(k, current.get(k)), "new": _shown(k, v)})
    return {
        "unknown_fields": [
            {"field": k, "did_you_mean": difflib.get_close_matches(k, list(current), n=3)} for k in unknown
        ],
        "changes": diff,
        "already_set": unchanged,
    }


def verify_patch(before: dict[str, Any], after: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Check that requested fields have the new values and nothing else changed."""
    not_applied = [k for k, v in changes.items() if not _same(after.get(k), v)]
    unexpected = sorted(
        k for k in set(before) | set(after)
        if k not in changes and not str(k).startswith("q_") and not _same(before.get(k), after.get(k))
    )
    return {
        "verified": not not_applied and not unexpected,
        "not_applied": not_applied,
        "unexpected_changes": unexpected,
    }


def register(mcp: FastMCP) -> None:
    """Register the extended tools."""
    register_more(mcp)

    @mcp.tool()
    async def device_info(
        ctx: Context,
        vdom: Annotated[str | None, _VDOM_FIELD] = None,
    ) -> dict[str, Any]:
        """Live identity of the connected FortiGate: hostname, model, serial, FortiOS
        version and build, read from /api/v2/monitor/system/status.

        Use this (not the server description) to know the real FortiOS version.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            resp = await client.monitor_get("system/status", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
        r = resp.get("results") if isinstance(resp.get("results"), dict) else {}
        return {
            "hostname": r.get("hostname"),
            "model": r.get("model"),
            "model_name": r.get("model_name"),
            "model_number": r.get("model_number"),
            "serial": resp.get("serial"),
            "version": resp.get("version"),
            "build": resp.get("build"),
            "vdom": resp.get("vdom"),
            "source": "monitor/system/status",
        }

    @mcp.tool()
    async def cmdb_schema(
        ctx: Context,
        resource_path: Annotated[
            str,
            Field(
                description=(
                    "CMDB collection path without key, e.g. 'firewall/policy', "
                    "'firewall/ssl-ssh-profile', 'vpn.ipsec/phase1-interface'."
                )
            ),
        ],
        field: Annotated[
            str | None,
            Field(default=None, description="Optional: return the full schema of just this field."),
        ] = None,
        vdom: Annotated[str | None, _VDOM_FIELD] = None,
    ) -> dict[str, Any]:
        """Field schema of a CMDB endpoint as reported by this device (GET ?action=schema):
        field names, types, options, sizes and defaults for its exact model and FortiOS
        version. Use it to build or check config before writing."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            # schema has no secret values; raw keeps field definitions intact
            resp = await client.cmdb_get(resource_path, {"action": "schema"}, vdom=vdom, raw=True)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
        return summarize_schema(resp, field)

    @mcp.tool()
    async def cmdb_patch(
        ctx: Context,
        resource_path: Annotated[
            str,
            Field(description="Full CMDB path including the key, e.g. 'firewall/policy/12', 'system/interface/port3'."),
        ],
        changes: Annotated[
            str,
            Field(
                description=(
                    "JSON object with ONLY the fields to change, e.g. '{\"status\": \"disable\"}' or "
                    "'{\"srcaddr\": [{\"name\": \"LAN-net\"}]}'. List fields replace the whole list."
                )
            ),
        ],
        dry_run: Annotated[
            bool,
            Field(default=True, description="True (default): only show the diff. False: write and verify."),
        ] = True,
        vdom: Annotated[str | None, _VDOM_FIELD] = None,
    ) -> dict[str, Any]:
        """Safely change only some fields of one CMDB object.

        Reads the current object, rejects unknown fields, and returns the diff.
        With dry_run=false it writes only the changed fields, reads the object back,
        and reports whether every change was applied and whether anything else changed.
        Values of secret fields are never shown.
        """
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            wanted = json.loads(changes)
        except json.JSONDecodeError as exc:
            return {"error": f"Invalid JSON in changes: {exc}"}
        if not isinstance(wanted, dict) or not wanted:
            return {"error": "changes must be a non-empty JSON object"}
        if contains_redaction_marker(wanted):
            return {"error": "changes contain '<REDACTED>'; leave secret fields out to keep their value"}

        try:
            current = _first_result(await client.cmdb_get(resource_path, vdom=vdom, raw=True))
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
        if current is None:
            return {"error": f"object not found: {resource_path}"}

        plan = plan_patch(current, wanted)
        result: dict[str, Any] = {"resource_path": resource_path, "vdom": vdom, "dry_run": dry_run, **plan}
        if plan["unknown_fields"]:
            result["error"] = "unknown fields; nothing written"
            return result
        if not plan["changes"]:
            result["message"] = "all requested values are already set; nothing to write"
            return result
        if dry_run:
            result["message"] = "dry run: nothing written. Call again with dry_run=false after approval."
            return result

        to_write = {c["field"]: wanted[c["field"]] for c in plan["changes"]}
        try:
            write = await client.cmdb_put(resource_path, to_write, vdom=vdom)
            after = _first_result(await client.cmdb_get(resource_path, vdom=vdom, raw=True)) or {}
        except FortiOSError as exc:
            result["error"] = f"write or read-back failed: {exc}. Read the object before retrying."
            return result
        result["write_status"] = write.get("status")
        result["verification"] = verify_patch(current, after, to_write)
        return result


# ── order, clone, existence, discovery, log search ─────────────────────


async def _mkey_field(client: FortiOSClient, collection: str, vdom: str | None) -> str | None:
    try:
        schema = await client.cmdb_get(collection, {"action": "schema"}, vdom=vdom, raw=True)
    except FortiOSError:
        return None
    return (schema.get("results") or {}).get("mkey")


async def _order(client: FortiOSClient, collection: str, mkey: str, vdom: str | None) -> list[str]:
    resp = await client.cmdb_get(collection, {"format": mkey}, vdom=vdom)
    return [str(r.get(mkey)) for r in resp.get("results", []) if isinstance(r, dict)]


def _split(resource_path: str) -> tuple[str, str]:
    collection, _, key = resource_path.rstrip("/").rpartition("/")
    if not collection or not key:
        raise ValueError("resource_path must include the key, e.g. 'firewall/policy/12'")
    return collection, key


def register_more(mcp: FastMCP) -> None:
    """Register move, clone, exists, directory and log search tools."""

    @mcp.tool()
    async def cmdb_exists(
        ctx: Context,
        resource_path: Annotated[str, Field(description="Full CMDB path with key, e.g. 'firewall/address/web-srv'.")],
        vdom: Annotated[str | None, _VDOM_FIELD] = None,
    ) -> dict[str, Any]:
        """Return whether one CMDB object exists (true/false) without returning its content."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            resp = await client.cmdb_get(resource_path, vdom=vdom)
        except FortiOSError as exc:
            if exc.status_code == 404:
                return {"resource_path": resource_path, "exists": False}
            return {"error": str(exc), "status_code": exc.status_code}
        return {"resource_path": resource_path, "exists": _first_result(resp) is not None}

    @mcp.tool()
    async def cmdb_move(
        ctx: Context,
        resource_path: Annotated[str, Field(description="Object to move, with key, e.g. 'firewall/policy/12'.")],
        position: Annotated[str, Field(description="'before' or 'after'.")],
        neighbor_key: Annotated[str, Field(description="Key of the object to move before/after, e.g. '5'.")],
        dry_run: Annotated[bool, Field(default=True, description="True (default): show current order only.")] = True,
        vdom: Annotated[str | None, _VDOM_FIELD] = None,
    ) -> dict[str, Any]:
        """Change the order of an object in any ordered CMDB table (policies, local-in policies,
        policy routes, SD-WAN rules, ...) with PUT ?action=move&before|after=<key>.
        Reads the order before and, after writing, reads it again to verify."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        if position not in ("before", "after"):
            return {"error": "position must be 'before' or 'after'"}
        try:
            collection, key = _split(resource_path)
        except ValueError as exc:
            return {"error": str(exc)}
        mkey = await _mkey_field(client, collection, vdom)
        if not mkey:
            return {"error": f"could not read the key field of '{collection}' from its schema"}
        try:
            order = await _order(client, collection, mkey, vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
        missing = [k for k in (key, str(neighbor_key)) if k not in order]
        result: dict[str, Any] = {"resource_path": resource_path, "position": position,
                                  "neighbor_key": str(neighbor_key), "dry_run": dry_run,
                                  "current_index": order.index(key) if key in order else None,
                                  "neighbor_index": order.index(str(neighbor_key)) if str(neighbor_key) in order else None}
        if missing:
            result["error"] = f"not found in {collection}: {missing}"
            return result
        if dry_run:
            result["message"] = "dry run: nothing written. Call again with dry_run=false after approval."
            return result
        try:
            write = await client.cmdb_put(resource_path, {}, params={"action": "move", position: str(neighbor_key)},
                                          vdom=vdom)
            after = await _order(client, collection, mkey, vdom)
        except FortiOSError as exc:
            result["error"] = f"move or read-back failed: {exc}. Read the order before retrying."
            return result
        i, j = after.index(key), after.index(str(neighbor_key))
        result["write_status"] = write.get("status")
        result["verification"] = {"verified": (i == j - 1) if position == "before" else (i == j + 1),
                                  "new_index": i, "neighbor_index": j}
        return result

    @mcp.tool()
    async def cmdb_clone(
        ctx: Context,
        resource_path: Annotated[str, Field(description="Object to copy, with key, e.g. 'firewall/address/web-srv'.")],
        new_key: Annotated[str, Field(description="Key (name/ID) of the copy.")],
        dry_run: Annotated[bool, Field(default=True, description="True (default): only check source and new key.")] = True,
        vdom: Annotated[str | None, _VDOM_FIELD] = None,
    ) -> dict[str, Any]:
        """Copy a CMDB object to a new key with POST ?action=clone&nkey=<new_key>, then verify the copy exists."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            collection, _key = _split(resource_path)
        except ValueError as exc:
            return {"error": str(exc)}

        async def exists(path: str) -> bool:
            try:
                return _first_result(await client.cmdb_get(path, vdom=vdom)) is not None
            except FortiOSError as exc:
                if exc.status_code == 404:
                    return False
                raise

        try:
            src, dst = await exists(resource_path), await exists(f"{collection}/{new_key}")
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
        result: dict[str, Any] = {"resource_path": resource_path, "new_key": new_key, "dry_run": dry_run}
        if not src:
            result["error"] = "source object does not exist"
            return result
        if dst:
            result["error"] = f"'{collection}/{new_key}' already exists"
            return result
        if dry_run:
            result["message"] = "dry run: nothing written. Call again with dry_run=false after approval."
            return result
        try:
            write = await client.cmdb_post(resource_path, {}, params={"action": "clone", "nkey": new_key}, vdom=vdom)
            ok = await exists(f"{collection}/{new_key}")
        except FortiOSError as exc:
            result["error"] = f"clone or read-back failed: {exc}"
            return result
        result["write_status"] = write.get("status")
        result["verification"] = {"verified": ok}
        return result

    @mcp.tool()
    async def api_directory(
        ctx: Context,
        section: Annotated[str, Field(description="'cmdb', 'monitor', 'log' or 'service'.")],
        path: Annotated[str, Field(default="", description="Optional sub-path, e.g. 'firewall' or 'system'.")] = "",
        vdom: Annotated[str | None, _VDOM_FIELD] = None,
    ) -> dict[str, Any]:
        """Ask the device which API endpoints exist (GET /api/v2/{section}/{path}). Use it to find
        the path for something that has no dedicated tool. The response format depends on the
        FortiOS version; an error means the device does not offer a directory there."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            resp = await client.section_get(section, path, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
        return {"section": section, "path": path, "directory": resp}

    @mcp.tool()
    async def log_search(
        ctx: Context,
        log_path: Annotated[str, Field(description="Log API path, e.g. 'disk/traffic/forward' or 'memory/event/system'.")],
        body: Annotated[
            str | None,
            Field(default=None, description="JSON body for the POST (e.g. search options supported by the device)."),
        ] = None,
        vdom: Annotated[str | None, _VDOM_FIELD] = None,
    ) -> dict[str, Any]:
        """POST to /api/v2/log/{log_path} for log endpoints that take a request body (e.g. search
        sessions). For simple reads with filters use log_get. Output is redacted."""
        client: FortiOSClient = ctx.request_context.lifespan_context["client"]
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError as exc:
            return {"error": f"Invalid JSON in body: {exc}"}
        try:
            return await client.log_post(log_path, payload, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}
