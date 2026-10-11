from __future__ import annotations

from types import SimpleNamespace

import pytest

from hermes_cli.external_request_guard import ExternalRequestBlocked
from hermes_cli.plugins import get_plugin_manager
from plugins.platforms.slack.adapter import _guard_slack_client


@pytest.mark.asyncio
async def test_slack_client_gate_blocks_before_sdk_call():
    calls = []

    async def api_call(method, *args, **kwargs):
        calls.append(method)
        return {"ok": True}

    client = SimpleNamespace(api_call=api_call)
    manager = get_plugin_manager()
    old = dict(manager._hooks)
    manager._hooks = {
        "pre_external_request": [lambda **kwargs: {"action": "block"}],
    }
    try:
        _guard_slack_client(client)
        with pytest.raises(ExternalRequestBlocked):
            await client.api_call("chat.postMessage", json={"text": "secret"})
    finally:
        manager._hooks = old

    assert calls == []


@pytest.mark.asyncio
async def test_slack_client_gate_wraps_once():
    calls = []

    async def api_call(method, *args, **kwargs):
        calls.append(method)
        return {"ok": True}

    client = SimpleNamespace(api_call=api_call)
    manager = get_plugin_manager()
    old = dict(manager._hooks)
    manager._hooks = {"pre_external_request": [lambda **kwargs: None]}
    try:
        assert _guard_slack_client(client) is client
        assert _guard_slack_client(client) is client
        assert await client.api_call("auth.test") == {"ok": True}
    finally:
        manager._hooks = old

    assert calls == ["auth.test"]


def test_slack_client_gate_ignores_clients_without_api_call_surface():
    client = SimpleNamespace(auth_test=lambda: {"ok": True})

    assert _guard_slack_client(client) is client
    assert not hasattr(client, "_hermes_external_request_guard")
