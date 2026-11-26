"""FortiOS REST API async HTTP client."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from redaction import contains_redaction_marker, redact

logger = logging.getLogger(__name__)


class FortiOSError(Exception):
    """Raised on FortiOS API errors."""

    def __init__(
        self, message: str, status_code: int = 0, data: dict | None = None
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.data = data or {}


class FortiOSClient:
    """Async client for the FortiOS 7.6.6 REST API (v2).

    Supports all four API sections:
    - ``/api/v2/cmdb/``   — Configuration Management DB (read/write)
    - ``/api/v2/monitor/`` — Real-time operational data (mostly read-only)
    - ``/api/v2/log/``    — Log retrieval
    - ``/api/v2/service/`` — Service operations (security rating, sniffer …)

    Authentication is done via Bearer token passed in the ``Authorization``
    header as required by FortiOS 7.6.x.

    Usage::

        async with FortiOSClient(host, token) as client:
            data = await client.cmdb_get("system/status")
    """

    _BASE = "/api/v2"

    def __init__(
        self,
        host: str,
        api_token: str,
        vdom: str = "root",
        verify_ssl: bool = False,
        timeout: float = 30.0,
        redact_output: bool = True,
    ) -> None:
        self.host = host.rstrip("/")
        self.api_token = api_token
        self.vdom = vdom
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        # Replace secret values (passwords, PSKs, keys, ENC values) in every response.
        self.redact_output = redact_output
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "FortiOSClient":
        self._client = httpx.AsyncClient(
            base_url=self.host,
            headers=self._auth_headers(),
            verify=self.verify_ssl,
            timeout=self.timeout,
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _client_guard(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError(
                "FortiOSClient must be used as an async context manager."
            )
        return self._client

    def _vdom_params(
        self, extra: dict[str, Any] | None = None, vdom: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"vdom": vdom or self.vdom}
        if extra:
            params.update({k: v for k, v in extra.items() if v is not None})
        return params

    @staticmethod
    def _check_request(body: Any) -> None:
        """Refuse to send a redacted placeholder back to the device."""
        if body is not None and contains_redaction_marker(body):
            raise FortiOSError(
                "Request contains '<REDACTED>'. A redacted secret cannot be written back; "
                "leave the field out so the device keeps its current value.",
                400,
            )

    def _check_response(self, resp: httpx.Response, raw: bool = False) -> dict[str, Any]:
        """Parse and validate a FortiOS JSON response.

        Secrets are redacted unless ``raw`` is True (internal use only, never
        returned to the AI client).
        """
        try:
            body: dict[str, Any] = resp.json()
        except Exception as exc:
            raise FortiOSError(
                f"Non-JSON response (HTTP {resp.status_code}): {resp.text[:300]}",
                resp.status_code,
            ) from exc

        if self.redact_output and not raw:
            body = redact(body)

        http_status: int = body.get("http_status", resp.status_code)
        if resp.status_code >= 400 or http_status >= 400:
            status_msg = body.get("status", "error")
            error_msg = body.get("cli_error", body.get("http_method", str(redact(body))))
            raise FortiOSError(
                f"FortiOS API error {http_status}: {status_msg} — {error_msg}",
                http_status,
                redact(body),
            )
        return body

    # ------------------------------------------------------------------
    # CMDB  (/api/v2/cmdb/…)
    # ------------------------------------------------------------------

    async def cmdb_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
        raw: bool = False,
    ) -> dict[str, Any]:
        """GET /api/v2/cmdb/{path} — retrieve configuration.

        ``raw=True`` skips redaction; only for internal read-modify-write logic.
        """
        client = self._client_guard()
        url = f"{self._BASE}/cmdb/{path.lstrip('/')}"
        resp = await client.get(url, params=self._vdom_params(params, vdom))
        return self._check_response(resp, raw=raw)

    async def cmdb_post(
        self,
        path: str,
        body: dict[str, Any],
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        """POST /api/v2/cmdb/{path} — create a configuration object."""
        self._check_request(body)
        client = self._client_guard()
        url = f"{self._BASE}/cmdb/{path.lstrip('/')}"
        resp = await client.post(url, json=body, params=self._vdom_params(params, vdom))
        return self._check_response(resp)

    async def cmdb_put(
        self,
        path: str,
        body: dict[str, Any],
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        """PUT /api/v2/cmdb/{path} — replace a configuration object."""
        self._check_request(body)
        client = self._client_guard()
        url = f"{self._BASE}/cmdb/{path.lstrip('/')}"
        resp = await client.put(url, json=body, params=self._vdom_params(params, vdom))
        return self._check_response(resp)

    async def cmdb_delete(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        """DELETE /api/v2/cmdb/{path} — remove a configuration object."""
        client = self._client_guard()
        url = f"{self._BASE}/cmdb/{path.lstrip('/')}"
        resp = await client.delete(url, params=self._vdom_params(params, vdom))
        return self._check_response(resp)

    async def section_get(
        self,
        section: str,
        path: str = "",
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any] | list[Any]:
        """GET /api/v2/{section}/{path} — used for API directory discovery.

        Some directory responses are a JSON list instead of an object.
        """
        if section not in ("cmdb", "monitor", "log", "service"):
            raise FortiOSError(f"unknown API section '{section}'", 400)
        client = self._client_guard()
        url = f"{self._BASE}/{section}/{path.lstrip('/')}"
        resp = await client.get(url, params=self._vdom_params(params, vdom))
        try:
            body = resp.json()
        except Exception as exc:
            raise FortiOSError(f"Non-JSON response (HTTP {resp.status_code}): {resp.text[:300]}",
                               resp.status_code) from exc
        if isinstance(body, list):
            if resp.status_code >= 400:
                raise FortiOSError(f"FortiOS API error {resp.status_code}", resp.status_code)
            return redact(body) if self.redact_output else body
        return self._check_response(resp)

    # ------------------------------------------------------------------
    # Monitor  (/api/v2/monitor/…)
    # ------------------------------------------------------------------

    async def monitor_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        """GET /api/v2/monitor/{path} — retrieve operational/real-time data."""
        client = self._client_guard()
        url = f"{self._BASE}/monitor/{path.lstrip('/')}"
        resp = await client.get(url, params=self._vdom_params(params, vdom))
        return self._check_response(resp)

    async def monitor_post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        """POST /api/v2/monitor/{path} — trigger a monitor action."""
        self._check_request(body)
        client = self._client_guard()
        url = f"{self._BASE}/monitor/{path.lstrip('/')}"
        resp = await client.post(
            url, json=body or {}, params=self._vdom_params(params, vdom)
        )
        return self._check_response(resp)

    # ------------------------------------------------------------------
    # Log  (/api/v2/log/…)
    # ------------------------------------------------------------------

    async def log_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        """GET /api/v2/log/{path} — retrieve log entries."""
        client = self._client_guard()
        url = f"{self._BASE}/log/{path.lstrip('/')}"
        resp = await client.get(url, params=self._vdom_params(params, vdom))
        return self._check_response(resp)

    async def log_post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        """POST /api/v2/log/{path} — start a log search or action."""
        self._check_request(body)
        client = self._client_guard()
        url = f"{self._BASE}/log/{path.lstrip('/')}"
        resp = await client.post(
            url, json=body or {}, params=self._vdom_params(params, vdom)
        )
        return self._check_response(resp)

    # ------------------------------------------------------------------
    # Service  (/api/v2/service/…)
    # ------------------------------------------------------------------

    async def service_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        """GET /api/v2/service/{path}."""
        client = self._client_guard()
        url = f"{self._BASE}/service/{path.lstrip('/')}"
        resp = await client.get(url, params=self._vdom_params(params, vdom))
        return self._check_response(resp)

    async def service_post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        vdom: str | None = None,
    ) -> dict[str, Any]:
        """POST /api/v2/service/{path}."""
        self._check_request(body)
        client = self._client_guard()
        url = f"{self._BASE}/service/{path.lstrip('/')}"
        resp = await client.post(
            url, json=body or {}, params=self._vdom_params(params, vdom)
        )
        return self._check_response(resp)
