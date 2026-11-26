"""SSH runner for FortiGate CLI diagnostics (debug and packet capture).

One interactive CLI session per call: send setup commands, collect output for a
bounded time (or until a stop condition), then ALWAYS send the cleanup commands,
even after an error or timeout. If the session broke, cleanup is sent again over
a fresh connection.

Author: Ehsan Emad (CyberKnightLabs)
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)

PROMPT = re.compile(r"(?m)^[\w.\-]+( \([\w.\-]+\))? [#$] ?$")
MORE = "--More--"


class SSHNotConfigured(RuntimeError):
    """SSH credentials are missing for this device."""


@dataclass
class SessionResult:
    output: str
    cleanup_ok: bool
    cleanup_output: str = ""
    truncated: bool = False
    commands: list[str] = field(default_factory=list)
    error: str | None = None


class FortiSSH:
    """Minimal asyncssh based CLI session runner."""

    def __init__(self, host: str | None, port: int = 22, username: str | None = None,
                 password: str | None = None, known_hosts: str | None = None, connect_timeout: float = 10.0):
        self.host, self.port, self.username = host, port, username
        self._password, self.known_hosts, self.connect_timeout = password, known_hosts, connect_timeout

    @property
    def configured(self) -> bool:
        return bool(self.host and self.username and self._password and self.known_hosts)

    def _require(self) -> None:
        if not self.configured:
            raise SSHNotConfigured(
                "SSH is not configured for this device (host key, username or password missing). "
                "The user must run: .venv/bin/python ssh_setup.py <device> and restart the AI client."
            )

    async def _connect(self):
        import asyncssh  # imported lazily so the server starts without it

        return await asyncio.wait_for(
            asyncssh.connect(self.host, port=self.port, username=self.username, password=self._password,
                             known_hosts=self.known_hosts, client_keys=None, agent_path=None),
            timeout=self.connect_timeout,
        )

    async def _drain(self, proc, seconds: float, stop: Callable[[str], bool] | None, max_chars: int) -> tuple[str, bool]:
        buf, deadline = "", time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=max(0.1, deadline - time.monotonic()))
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
            if MORE in chunk:
                proc.stdin.write(" ")
            if len(buf) > max_chars:
                return buf[:max_chars], True
            if stop and stop(buf):
                break
        return buf, False

    async def run_session(self, setup: list[str], collect_seconds: float, cleanup: list[str],
                          stop: Callable[[str], bool] | None = None, interrupt_first: bool = False,
                          max_chars: int = 200_000) -> SessionResult:
        """Run setup commands, collect output, then always run cleanup."""
        self._require()
        output, truncated, cleanup_ok, cleanup_out, error = "", False, False, "", None
        conn = proc = None
        try:
            conn = await self._connect()
            proc = await conn.create_process(term_type="vt100", term_size=(200, 50), encoding="utf-8",
                                             errors="replace")
            await self._drain(proc, 2.0, lambda b: bool(PROMPT.search(b)), 20_000)   # login banner + prompt
            for cmd in setup:
                proc.stdin.write(cmd + "\n")
                await asyncio.sleep(0.3)
            output, truncated = await self._drain(proc, collect_seconds, stop, max_chars)
        except Exception as exc:  # report, but never skip cleanup
            error = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                if proc is None:
                    raise ConnectionError("no session")
                if interrupt_first:
                    proc.stdin.write("\x03")
                    await asyncio.sleep(0.5)
                for cmd in cleanup:
                    proc.stdin.write(cmd + "\n")
                    await asyncio.sleep(0.3)
                cleanup_out, _ = await self._drain(proc, 2.0, None, 20_000)
                cleanup_ok = True
            except Exception as exc:  # session broken: retry cleanup on a fresh connection
                logger.warning("cleanup on the session failed (%s); retrying on a new connection", exc)
                cleanup_ok, cleanup_out = await self._cleanup_fresh(cleanup)
            finally:
                if conn is not None:
                    conn.close()
        return SessionResult(output=output, cleanup_ok=cleanup_ok, cleanup_output=cleanup_out,
                             truncated=truncated, commands=setup + cleanup, error=error)

    async def _cleanup_fresh(self, cleanup: list[str]) -> tuple[bool, str]:
        if not cleanup:
            return True, ""
        try:
            conn = await self._connect()
            try:
                proc = await conn.create_process(term_type="vt100", encoding="utf-8", errors="replace")
                await self._drain(proc, 2.0, lambda b: bool(PROMPT.search(b)), 20_000)
                for cmd in cleanup:
                    proc.stdin.write(cmd + "\n")
                    await asyncio.sleep(0.3)
                out, _ = await self._drain(proc, 2.0, None, 20_000)
                return True, out
            finally:
                conn.close()
        except Exception as exc:
            logger.error("cleanup retry failed: %s", exc)
            return False, f"cleanup failed: {exc}"
