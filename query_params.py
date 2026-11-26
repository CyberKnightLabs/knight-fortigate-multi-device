"""Validation of optional FortiOS REST query parameters for CMDB reads.

Only documented read options are passed through; anything else is refused so a
read tool can never be turned into a write (e.g. ``action=move``).
Parameter names follow the FortiOS REST API (FNDN). Support can differ between
FortiOS versions; the device returns an error for an option it does not know.

Author: Ehsan Emad (CyberKnightLabs)
"""

from __future__ import annotations

import json
from typing import Any

READ_PARAMS = {
    "datasource": "bool: include datasource information for each linked object",
    "with_meta": "bool: include meta information (referenced count, ...)",
    "with_contents_hash": "bool: include a checksum of each object's contents",
    "skip": "bool: skip non-applicable / default properties",
    "exclude-default-values": "bool: leave out fields that still have their default value",
    "scope": "'global' | 'vdom' | 'both'",
    "key": "string: field name to match with 'pattern'",
    "pattern": "string: value to match in field 'key'",
    "format": "string: 'field1|field2' to return only these fields",
    "filter": "string: e.g. 'name=@lan' (FortiOS filter syntax)",
    "start": "int: pagination offset",
    "count": "int: maximum number of results",
    "action": "'default' | 'meta' | 'schema' | 'revision' (read actions only)",
}
_READ_ACTIONS = {"default", "meta", "schema", "revision"}
_SCOPES = {"global", "vdom", "both"}


class ParamError(ValueError):
    """Invalid query parameter."""


def parse_read_params(raw: str | None) -> dict[str, Any] | None:
    """Parse and validate a JSON string of read-only query parameters."""
    if not raw:
        return None
    try:
        params = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ParamError(f"params is not valid JSON: {exc}") from exc
    if not isinstance(params, dict):
        raise ParamError("params must be a JSON object")
    unknown = sorted(set(params) - set(READ_PARAMS))
    if unknown:
        raise ParamError(f"unsupported params {unknown}; allowed: {sorted(READ_PARAMS)}")
    if "action" in params and params["action"] not in _READ_ACTIONS:
        raise ParamError(f"action must be one of {sorted(_READ_ACTIONS)} for read tools")
    if "scope" in params and params["scope"] not in _SCOPES:
        raise ParamError(f"scope must be one of {sorted(_SCOPES)}")
    out: dict[str, Any] = {}
    for k, v in params.items():
        if isinstance(v, bool):
            v = "true" if v else "false"   # FortiOS expects lowercase strings in the query
        out[k] = v
    return out
