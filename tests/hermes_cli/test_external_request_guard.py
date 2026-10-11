from __future__ import annotations

import pytest

from hermes_cli.external_request_guard import ExternalRequestBlocked, guard_external_request
from hermes_cli.plugins import get_plugin_manager


@pytest.fixture(autouse=True)
def isolated_hooks():
    manager = get_plugin_manager()
    old = dict(manager._hooks)
    manager._hooks = {}
    try:
        yield manager
    finally:
        manager._hooks = old


def test_no_listener_is_noop():
    with guard_external_request("inference", "model_request") as request_id:
        assert request_id == ""


def test_block_directive_denies_and_runs_cleanup(isolated_hooks):
    events = []
    isolated_hooks._hooks["pre_external_request"] = [
        lambda **kwargs: {"action": "block", "message": "expired authorization"}
    ]
    isolated_hooks._hooks["post_external_request"] = [
        lambda **kwargs: events.append(kwargs)
    ]

    with pytest.raises(ExternalRequestBlocked, match="denied by policy"):
        with guard_external_request("slack_api", "chat.postMessage"):
            raise AssertionError("request body must not run")

    assert events[0]["request_type"] == "slack_api"
    assert events[0]["operation"] == "chat.postMessage"
    assert events[0]["outcome"] == "denied"


def test_policy_exception_fails_closed_and_runs_cleanup(isolated_hooks):
    events = []

    def broken_policy(**kwargs):
        raise RuntimeError("policy unavailable")

    isolated_hooks._hooks["pre_external_request"] = [broken_policy]
    isolated_hooks._hooks["post_external_request"] = [
        lambda **kwargs: events.append(kwargs)
    ]

    with pytest.raises(ExternalRequestBlocked, match="policy gate failed"):
        with guard_external_request("oauth_refresh", "openai_codex"):
            raise AssertionError("request body must not run")

    assert events[0]["outcome"] == "denied"


def test_admitted_request_pairs_same_id_and_reports_failure(isolated_hooks):
    pre = []
    post = []
    isolated_hooks._hooks["pre_external_request"] = [
        lambda **kwargs: pre.append(kwargs)
    ]
    isolated_hooks._hooks["post_external_request"] = [
        lambda **kwargs: post.append(kwargs)
    ]

    with pytest.raises(ValueError, match="upstream failed"):
        with guard_external_request("inference", "model_request") as request_id:
            assert request_id
            raise ValueError("upstream failed")

    assert post[0]["external_request_id"] == pre[0]["external_request_id"]
    assert post[0]["outcome"] == "failed"


def test_payload_never_contains_request_secrets(isolated_hooks):
    observed = []
    isolated_hooks._hooks["pre_external_request"] = [
        lambda **kwargs: observed.append(kwargs)
    ]

    with guard_external_request(
        "slack_api",
        "chat.postMessage",
        task_id="task-1",
        user_id="user-1",
        headers={"Authorization": "secret"},
        body={"text": "secret"},
        token="secret",
    ):
        pass

    assert observed[0]["task_id"] == "task-1"
    assert observed[0].get("user_id") != "user-1"
    assert "headers" not in observed[0]
    assert "body" not in observed[0]
    assert "token" not in observed[0]
