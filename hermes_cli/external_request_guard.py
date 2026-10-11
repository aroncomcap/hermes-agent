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
from typing import Any, AsyncIterator, Awaitable, Callable, TypeVar


logger = logging.getLogger(__name__)

_T = TypeVar("_T")


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
        self._egress_gate = threading.Condition()
        self._active_egress = 0
        self._revoking = False
        self._pending_lock = threading.Lock()
        self._pending_terminal: dict[str, tuple[ExternalRequestPermit, str]] = {}
        self._reconciler: threading.Thread | None = None
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

    def _assert_active_locked(self, permit: ExternalRequestPermit) -> None:
        self._initialize()
        with self._connect() as connection:
            generation = self._generation(connection)
            row = connection.execute(
                "SELECT state FROM external_request_attempts WHERE request_id = ?",
                (permit.request_id,),
            ).fetchone()
        if generation != permit.generation or row != ("admitted",):
            raise ExternalRequestBlocked("External request permit was revoked")

    def _begin_egress(self, permit: ExternalRequestPermit) -> None:
        with self._egress_gate:
            while self._revoking:
                self._egress_gate.wait()
            self._active_egress += 1
        try:
            with self._lock:
                self._assert_active_locked(permit)
        except BaseException:
            self._end_egress()
            raise

    def _end_egress(self) -> None:
        with self._egress_gate:
            self._active_egress -= 1
            if self._active_egress == 0:
                self._egress_gate.notify_all()

    def egress_sync(
        self, permit: ExternalRequestPermit, operation: Callable[[], _T]
    ) -> _T:
        """Run one wire operation while revocation is linearly excluded."""
        self._begin_egress(permit)
        try:
            return operation()
        finally:
            self._end_egress()

    async def egress(
        self, permit: ExternalRequestPermit, operation: Callable[[], Awaitable[_T]]
    ) -> _T:
        await asyncio.to_thread(self._begin_egress, permit)
        try:
            return await operation()
        finally:
            self._end_egress()

    def _complete_once(self, permit: ExternalRequestPermit, terminal: str) -> bool:
        from hermes_cli.plugins import invoke_hook

        self._initialize()
        with self._connect() as connection:
            cursor = connection.execute(
                """UPDATE external_request_attempts
                   SET state = ?, terminal_at = ?
                   WHERE request_id = ? AND state = 'admitted'""",
                (terminal, time.time(), permit.request_id),
            )
        if cursor.rowcount == 1:
            invoke_hook("post_external_request", **permit.payload, outcome=terminal)
        return cursor.rowcount == 1

    def _defer_completion(
        self, permit: ExternalRequestPermit, terminal: str
    ) -> None:
        with self._pending_lock:
            self._pending_terminal.setdefault(permit.request_id, (permit, terminal))
            if self._reconciler is not None and self._reconciler.is_alive():
                return
            self._reconciler = threading.Thread(
                target=self._reconcile_pending,
                name="external-request-reconciler",
                daemon=True,
            )
            self._reconciler.start()

    def _reconcile_pending(self) -> None:
        delay = 0.05
        while True:
            with self._pending_lock:
                pending = list(self._pending_terminal.items())
            if not pending:
                return
            progressed = False
            for request_id, (permit, terminal) in pending:
                try:
                    reconciled = self._complete_once(permit, terminal)
                except Exception:
                    continue
                if reconciled:
                    progressed = True
                with self._pending_lock:
                    current = self._pending_terminal.get(request_id)
                    if current == (permit, terminal):
                        self._pending_terminal.pop(request_id, None)
            if not progressed:
                time.sleep(delay)
                delay = min(delay * 2, 5.0)
            else:
                delay = 0.05

    def complete_sync(self, permit: ExternalRequestPermit, state: str) -> bool:
        terminal = state if state in {"completed", "failed", "cancelled", "abandoned"} else "failed"
        try:
            return self._complete_once(permit, terminal)
        except Exception:
            logger.exception(
                "External request terminal reconciliation deferred for %s",
                permit.request_id,
            )
            self._defer_completion(permit, terminal)
            return False

    async def complete(self, permit: ExternalRequestPermit, state: str) -> None:
        await asyncio.to_thread(self.complete_sync, permit, state)

    def revoke_sync(self) -> int:
        with self._egress_gate:
            self._revoking = True
            while self._active_egress:
                self._egress_gate.wait()
        try:
            with self._lock:
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
        finally:
            with self._egress_gate:
                self._revoking = False
                self._egress_gate.notify_all()

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
