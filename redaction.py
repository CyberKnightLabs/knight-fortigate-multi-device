"""Secret redaction for FortiOS API responses.

Every response returned to the AI client passes through :func:`redact` so that
passwords, pre-shared keys, API keys, private keys and FortiOS ``ENC`` values
never reach the model context. Requests are checked with
:func:`contains_redaction_marker` so a redacted value can never be written back
to the device by mistake.

Author: Ehsan Emad (CyberKnightLabs)
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "<REDACTED>"

# Field names whose values are secrets (FortiOS uses kebab-case keys).
_SECRET_KEY = re.compile(
    r"(^|[-_])("
    r"password|passwd|passwd[0-9]|pwd|psksecret|psksecret-remote|psk|secret|"
    r"private-key|key|api-key|apikey|token|access-token|refresh-token|"
    r"community|passphrase|auth-pwd|priv-pwd|auth-password|priv-password|"
    r"ppk-secret|sso-password|ldap-password|server-key|client-key|"
    r"secondary-secret|tertiary-secret|radius-secret|tacacs-key"
    r")([-_]?[0-9]*)$",
    re.IGNORECASE,
)

# Field names that look like secrets but are not (lengths, types, flags).
_NOT_SECRET = re.compile(
    r"(^|[-_])(key-?(type|size|length|life|lifekbs|lifeseconds|usage|id|exchange)|"
    r"keylife.*|password-?(policy|expire.*|length|change|age|reuse|min.*|max.*|history|"
    r"attempts?|strength|renewal|safe)|psk-?(type|mode)|token-?(type|status|id))$",
    re.IGNORECASE,
)

_SECRET_VALUE = re.compile(r"^\s*(ENC\s+\S+|-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----)", re.IGNORECASE)


def is_secret_key(key: str) -> bool:
    """Return True if a field name holds a secret value."""
    return bool(_SECRET_KEY.search(key)) and not _NOT_SECRET.search(key)


def redact(obj: Any) -> Any:
    """Return a deep copy of ``obj`` with secret values replaced by ``<REDACTED>``."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and is_secret_key(k) and v not in (None, "", [], {}):
                out[k] = REDACTED
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str) and _SECRET_VALUE.search(obj):
        return REDACTED
    return obj


_TEXT_SECRETS = [
    (re.compile(r"ENC\s+\S+"), "ENC " + REDACTED),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), REDACTED),
    (re.compile(r"(?i)\b((?:enc|auth|ah|esp)?[ _-]?key\s*[=:]\s*(?:\d+\s+)?)[0-9a-f]{16,}"), r"\1" + REDACTED),
    (re.compile(r"(?i)\b(psk|psksecret|password|passwd|secret)\s*[=:]\s*\S+"), r"\1=" + REDACTED),
]


def redact_text(text: str) -> str:
    """Redact secrets in free-form CLI output (ENC values, private keys, SA keys, key=value secrets)."""
    for rx, repl in _TEXT_SECRETS:
        text = rx.sub(repl, text)
    return text


def contains_redaction_marker(obj: Any) -> bool:
    """True if ``obj`` contains the redaction marker anywhere (must not be written)."""
    if isinstance(obj, dict):
        return any(contains_redaction_marker(v) for v in obj.values())
    if isinstance(obj, list):
        return any(contains_redaction_marker(v) for v in obj)
    return isinstance(obj, str) and REDACTED in obj
