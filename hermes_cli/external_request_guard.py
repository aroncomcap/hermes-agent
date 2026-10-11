"""Fail-closed plugin gate for protected outbound requests.

The pre hook may return ``{"action": "block", "message": "..."}``. Hook
failures deny the request. The paired post hook is best-effort and always runs
after pre-hook processing so plugins can release request-scoped locks.
"""

from __future__ import annotations

from contextlib import contextmanager
import uuid
from typing import Any, Iterator


_ALLOWED_CONTEXT_KEYS = frozenset(
    {"api_request_id", "model", "provider", "task_id", "turn_id"}
)


class ExternalRequestBlocked(PermissionError):
    """A protected outbound request was denied by policy."""


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


@contextmanager
def guard_external_request(
    request_type: str,
    operation: str,
    **context: Any,
) -> Iterator[str]:
    """Authorize one outbound request and pair it with a cleanup hook.

    No request body, headers, credentials, or response data are included in
    the hook payload. Policy plugins receive stable request/session identity
    plus the request type and operation only.
    """
    from hermes_cli.plugins import invoke_hook, invoke_hook_strict

    request_id = uuid.uuid4().hex
    payload: dict[str, Any] = _session_context()
    payload.update(
        {key: value for key, value in context.items() if key in _ALLOWED_CONTEXT_KEYS}
    )
    payload.update(
        external_request_id=request_id,
        request_type=str(request_type),
        operation=str(operation),
    )
    outcome = "denied"
    try:
        try:
            directives = invoke_hook_strict("pre_external_request", **payload)
        except Exception as exc:
            raise ExternalRequestBlocked(
                "External request denied: policy gate failed"
            ) from exc

        for directive in directives:
            if (
                isinstance(directive, dict)
                and str(directive.get("action", "")).lower() == "block"
            ):
                raise ExternalRequestBlocked("External request denied by policy")

        outcome = "completed"
        yield request_id
    except BaseException:
        if outcome == "completed":
            outcome = "failed"
        raise
    finally:
        invoke_hook("post_external_request", **payload, outcome=outcome)
