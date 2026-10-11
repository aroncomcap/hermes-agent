from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading

import pytest

from hermes_cli.external_request_guard import (
    ExternalRequestBlocked,
    ExternalRequestController,
)
from hermes_cli.plugins import get_plugin_manager


@pytest.fixture(autouse=True)
def isolated_hooks():
    manager = get_plugin_manager()
    previous = dict(manager._hooks)
    manager._hooks = {}
    try:
        yield manager
    finally:
        manager._hooks = previous


@pytest.mark.asyncio
async def test_admission_is_durable_before_return(tmp_path):
    journal = tmp_path / "requests.sqlite3"
    controller = ExternalRequestController(journal)

    permit = await controller.admit("slack_http", "slack_web_api")

    with sqlite3.connect(journal) as connection:
        row = connection.execute(
            "SELECT generation, state FROM external_request_attempts WHERE request_id = ?",
            (permit.request_id,),
        ).fetchone()
    assert row == (1, "admitted")


@pytest.mark.asyncio
async def test_policy_failure_denies_without_admission(tmp_path, isolated_hooks):
    isolated_hooks._hooks["pre_external_request"] = [
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("sink unavailable"))
    ]
    journal = tmp_path / "requests.sqlite3"
    controller = ExternalRequestController(journal)

    with pytest.raises(ExternalRequestBlocked, match="durable admission failed"):
        await controller.admit("slack_http", "slack_web_api")

    assert not journal.exists()


@pytest.mark.asyncio
async def test_completion_is_idempotent_and_revocation_advances_generation(
    tmp_path, isolated_hooks
):
    journal = tmp_path / "requests.sqlite3"
    controller = ExternalRequestController(journal)
    outcomes = []
    isolated_hooks._hooks["post_external_request"] = [
        lambda **kwargs: outcomes.append(kwargs["outcome"])
    ]
    first = await controller.admit("slack_socket_frame", "ack")
    await controller.complete(first, "completed")
    await controller.complete(first, "failed")
    generation = await controller.revoke()
    second = await controller.admit("slack_socket_frame", "ack")

    with sqlite3.connect(journal) as connection:
        state = connection.execute(
            "SELECT state FROM external_request_attempts WHERE request_id = ?",
            (first.request_id,),
        ).fetchone()[0]
    assert state == "completed"
    assert outcomes == ["completed"]
    assert generation == 2
    assert second.generation == 2


@pytest.mark.asyncio
async def test_cancellation_has_distinct_terminal_state(tmp_path):
    journal = tmp_path / "requests.sqlite3"
    controller = ExternalRequestController(journal)

    with pytest.raises(asyncio.CancelledError):
        async with controller.admission("model_inference", "stream") as permit:
            raise asyncio.CancelledError

    with sqlite3.connect(journal) as connection:
        state = connection.execute(
            "SELECT state FROM external_request_attempts WHERE request_id = ?",
            (permit.request_id,),
        ).fetchone()[0]
    assert state == "cancelled"


def test_revoke_linearizes_with_admission(tmp_path, isolated_hooks):
    controller = ExternalRequestController(tmp_path / "requests.sqlite3")
    hook_entered = threading.Event()
    release_hook = threading.Event()

    def blocking_hook(**_kwargs):
        hook_entered.set()
        assert release_hook.wait(timeout=2)

    isolated_hooks._hooks["pre_external_request"] = [blocking_hook]
    with ThreadPoolExecutor(max_workers=2) as pool:
        admitted = pool.submit(controller.admit_sync, "slack_socket_frame", "ack")
        assert hook_entered.wait(timeout=2)
        revoked = pool.submit(controller.revoke_sync)
        assert not revoked.done()
        release_hook.set()
        first = admitted.result(timeout=2)
        generation = revoked.result(timeout=2)

    isolated_hooks._hooks["pre_external_request"] = []
    second = controller.admit_sync("slack_socket_frame", "ack")
    assert first.generation == 1
    assert generation == 2
    assert second.generation == 2


def test_terminal_sink_failure_does_not_mask_completed_transport(tmp_path, monkeypatch):
    controller = ExternalRequestController(tmp_path / "requests.sqlite3")
    permit = controller.admit_sync("model_inference", "stream")

    monkeypatch.setattr(
        controller,
        "_connect",
        lambda: (_ for _ in ()).throw(sqlite3.OperationalError("sink unavailable")),
    )

    assert controller.complete_sync(permit, "completed") is False
