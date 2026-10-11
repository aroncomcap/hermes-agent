from __future__ import annotations

import pytest

from agent.anthropic_adapter import refresh_anthropic_oauth_pure
from hermes_cli.auth import refresh_codex_oauth_pure
from hermes_cli.external_request_guard import ExternalRequestBlocked
from hermes_cli.plugins import get_plugin_manager


@pytest.fixture
def blocking_gate():
    manager = get_plugin_manager()
    old = dict(manager._hooks)
    seen = []
    manager._hooks = {
        "pre_external_request": [
            lambda **kwargs: seen.append(kwargs) or {"action": "block"}
        ],
    }
    try:
        yield seen
    finally:
        manager._hooks = old


def test_codex_oauth_refresh_is_blocked_before_http(monkeypatch, blocking_gate):
    calls = []

    def forbidden_post(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("HTTP call must not run")

    monkeypatch.setattr("httpx.Client.post", forbidden_post)

    with pytest.raises(ExternalRequestBlocked):
        refresh_codex_oauth_pure("access", "refresh")

    assert calls == []
    assert blocking_gate[0]["request_type"] == "oauth_refresh"
    assert blocking_gate[0]["operation"] == "openai_codex"


def test_anthropic_oauth_refresh_is_blocked_without_retry(monkeypatch, blocking_gate):
    calls = []

    def forbidden_open(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("HTTP call must not run")

    monkeypatch.setattr("urllib.request.urlopen", forbidden_open)

    with pytest.raises(ExternalRequestBlocked):
        refresh_anthropic_oauth_pure("refresh")

    assert calls == []
    assert len(blocking_gate) == 1
    assert blocking_gate[0]["operation"] == "anthropic"
