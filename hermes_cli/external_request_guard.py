"""Durable, fail-closed admission for protected outbound operations."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
import os
import logging
from pathlib import Path
import sqlite3
import threading
import time
import uuid
from typing import Any, AsyncIterator


logger = logging.getLogger(__name__)


_ALLOWED_CONTEXT_KEYS = frozenset(
    {"api_request_id", "model", "provider", "task_id", "turn_id"}
)


class ExternalRequestBlocked(RuntimeError):
    """A protected outbound operation was denied before egress."""


@dataclass(frozen=True)
class ExternalRequestPermit:
    request_id: str
    generation: int
    request_type: str
    operation: str
    payload: dict[str, Any]


class ExternalRequestController:
    """Linearize generation changes and durably record request admissions."""

    def __init__(self, journal_path: Path | None = None) -> None:
        configured = os.environ.get("HERMES_EXTERNAL_REQUEST_JOURNAL", "")
        self._path = journal_path or Path(configured or "~/.hermes/external-requests.sqlite3").expanduser()
        self._lock = threading.Lock()
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        connection = sqlite3.connect(self._path, timeout=5)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        if self._initialized:
            return
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS external_request_meta (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO external_request_meta(key, value)
                VALUES ('generation', 1);
                CREATE TABLE IF NOT EXISTS external_request_attempts (
                    request_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL,
                    request_type TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    state TEXT NOT NULL,
                    admitted_at REAL NOT NULL,
                    terminal_at REAL
                );
                """
            )
        self._initialized = True

    def _generation(self, connection: sqlite3.Connection) -> int:
        row = connection.execute(
            "SELECT value FROM external_request_meta WHERE key = 'generation'"
        ).fetchone()
        if row is None:
            raise RuntimeError("external request generation is unavailable")
        return int(row[0])

    def admit_sync(
        self, request_type: str, operation: str, **context: Any
    ) -> ExternalRequestPermit:
        from hermes_cli.plugins import invoke_hook_strict

        request_id = uuid.uuid4().hex
        payload = _session_context()
        payload.update(
            {key: value for key, value in context.items() if key in _ALLOWED_CONTEXT_KEYS}
        )
        payload.update(
            external_request_id=request_id,
            request_type=str(request_type),
            operation=str(operation),
        )
        with self._lock:
            try:
                directives = invoke_hook_strict("pre_external_request", **payload)
                for directive in directives:
                    if isinstance(directive, dict) and str(
                        directive.get("action", "")
                    ).lower() == "block":
                        raise ExternalRequestBlocked("External request denied by policy")
                self._initialize()
                with self._connect() as connection:
                    generation = self._generation(connection)
                    connection.execute(
                        """INSERT INTO external_request_attempts
                           (request_id, generation, request_type, operation, state, admitted_at)
                           VALUES (?, ?, ?, ?, 'admitted', ?)""",
                        (request_id, generation, request_type, operation, time.time()),
                    )
            except ExternalRequestBlocked:
                raise
            except Exception as exc:
                raise ExternalRequestBlocked(
                    "External request denied: policy or durable admission failed"
                ) from exc
        return ExternalRequestPermit(
            request_id=request_id,
            generation=generation,
            request_type=request_type,
            operation=operation,
            payload=payload,
        )

    async def admit(
        self, request_type: str, operation: str, **context: Any
    ) -> ExternalRequestPermit:
        return await asyncio.to_thread(
            self.admit_sync, request_type, operation, **context
        )

    def complete_sync(self, permit: ExternalRequestPermit, state: str) -> bool:
        from hermes_cli.plugins import invoke_hook

        terminal = state if state in {"completed", "failed", "cancelled", "abandoned"} else "failed"
        try:
            self._initialize()
            with self._connect() as connection:
                cursor = connection.execute(
                    """UPDATE external_request_attempts
                       SET state = ?, terminal_at = ?
                       WHERE request_id = ? AND state = 'admitted'""",
                    (terminal, time.time(), permit.request_id),
                )
        except Exception:
            logger.exception(
                "External request terminal reconciliation deferred for %s",
                permit.request_id,
            )
            return False
        if cursor.rowcount == 1:
            invoke_hook("post_external_request", **permit.payload, outcome=terminal)
        return cursor.rowcount == 1

    async def complete(self, permit: ExternalRequestPermit, state: str) -> None:
        await asyncio.to_thread(self.complete_sync, permit, state)

    def revoke_sync(self) -> int:
        with self._lock:
            try:
                self._initialize()
                with self._connect() as connection:
                    generation = self._generation(connection) + 1
                    connection.execute(
                        "UPDATE external_request_meta SET value = ? WHERE key = 'generation'",
                        (generation,),
                    )
                return generation
            except Exception as exc:
                raise ExternalRequestBlocked(
                    "External request revocation failed closed"
                ) from exc

    async def revoke(self) -> int:
        return await asyncio.to_thread(self.revoke_sync)

    @asynccontextmanager
    async def admission(
        self, request_type: str, operation: str, **context: Any
    ) -> AsyncIterator[ExternalRequestPermit]:
        permit = await self.admit(request_type, operation, **context)
        state = "completed"
        try:
            yield permit
        except asyncio.CancelledError:
            state = "cancelled"
            raise
        except BaseException:
            state = "failed"
            raise
        finally:
            await self.complete(permit, state)


def _session_context() -> dict[str, str]:
    try:
        from gateway.session_context import get_session_env

        return {
            "platform": get_session_env("HERMES_SESSION_PLATFORM", ""),
            "session_key": get_session_env("HERMES_SESSION_KEY", ""),
            "session_id": get_session_env("HERMES_SESSION_ID", ""),
            "user_id": get_session_env("HERMES_SESSION_USER_ID", ""),
            "chat_id": get_session_env("HERMES_SESSION_CHAT_ID", ""),
        }
    except Exception:
        return {}


_controller: ExternalRequestController | None = None


def get_external_request_controller() -> ExternalRequestController:
    global _controller
    if _controller is None:
        _controller = ExternalRequestController()
    return _controller


def reset_external_request_controller_for_tests(
    controller: ExternalRequestController | None = None,
) -> None:
    global _controller
    _controller = controller
