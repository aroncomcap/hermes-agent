"""Security and lifecycle tests for brokered Slack transport.

These tests intentionally exercise the pinned Slack/aiohttp libraries while
making their Internet-bearing fallbacks fatal.  Brokered mode must remain
functional using only AF_UNIX.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from typing import Any, Awaitable, Callable
from unittest.mock import AsyncMock, Mock

import aiohttp
import pytest
from slack_bolt.request.async_request import AsyncBoltRequest
from slack_sdk.socket_mode.aiohttp import SocketModeClient as AiohttpSocketModeClient
from slack_sdk.web import async_base_client as slack_async_base_client

from plugins.platforms.slack.brokered import (
    BrokerIPCClient,
    BrokerProtocolError,
    BrokerSettings,
    BrokerSocketModeClient,
    BrokerTerminalDenied,
    BrokeredAsyncApp,
    BrokeredAsyncWebClient,
    SupervisorState,
)
from gateway.config import GatewayConfig, Platform, PlatformConfig, _apply_env_overrides
from plugins.platforms.slack.adapter import SlackAdapter


Handler = Callable[
    [dict[str, Any], asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]
]


async def _start_broker(tmp_path: Path, handler: Handler):
    socket_path = tmp_path / "broker.sock"

    async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            raw = await reader.readline()
            frame = json.loads(raw)
            await handler(frame, reader, writer)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_unix_server(accept, path=socket_path)
    return socket_path, server


def _response(request: dict[str, Any], *, status: str = "ok", result: Any = None):
    return {
        "version": 1,
        "type": "response",
        "profile_id": request["profile_id"],
        "request_id": request["request_id"],
        "status": status,
        "result": result,
        "error": "policy denied" if status == "denied" else None,
    }


async def _write(writer: asyncio.StreamWriter, frame: dict[str, Any]) -> None:
    writer.write(json.dumps(frame, separators=(",", ":")).encode() + b"\n")
    await writer.drain()


def _client(path: Path, profile: str = "prod") -> BrokerIPCClient:
    return BrokerIPCClient(
        BrokerSettings(
            socket_path=path,
            profile_id=profile,
            request_timeout=1,
            retry_base=0.001,
            retry_cap=0.002,
        )
    )


def test_brokered_mode_is_disabled_by_default():
    adapter = SlackAdapter(PlatformConfig(enabled=True, token="x", extra={}))

    assert adapter._brokered_egress is False
    assert adapter._broker_transport is None


def test_brokered_config_does_not_ingest_slack_credentials(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-ambient-secret")
    config = GatewayConfig(
        platforms={
            Platform.SLACK: PlatformConfig(
                enabled=True,
                token="xoxb-yaml-secret",
                extra={"brokered_egress": True},
            )
        }
    )

    _apply_env_overrides(config)

    assert config.platforms[Platform.SLACK].token is None


def test_pinned_async_app_accepts_credential_free_brokered_client(tmp_path: Path):
    app = BrokeredAsyncApp(
        _client(tmp_path / "missing.sock"),
        [{"team_id": "T1", "user_id": "U1", "team": "Workspace"}],
    )

    assert isinstance(app.client, BrokeredAsyncWebClient)
    assert app.client.token is None
    assert app.client.workspace_id == "T1"

    request = AsyncBoltRequest(
        body={"team_id": "T1", "event": {"type": "message"}},
        mode="socket_mode",
    )
    app._init_context(request)
    assert isinstance(request.context.client, BrokeredAsyncWebClient)
    assert request.context.client.workspace_id == "T1"


@pytest.mark.asyncio
async def test_web_api_and_upload_v2_never_use_closed_session_fallback_or_af_inet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    calls: list[str] = []

    async def handler(request, _reader, writer):
        operation = request["operation"]
        calls.append(operation)
        params = request["params"]
        if operation == "slack.web_api":
            method = params["api_method"]
            if method == "files.getUploadURLExternal":
                result = {"ok": True, "file_id": "F1", "upload_url": "https://files.slack.test/u"}
            elif method == "files.completeUploadExternal":
                result = {"ok": True, "files": [{"id": "F1"}]}
            else:
                result = {"ok": True, "ts": "1.2"}
        else:
            assert operation == "http.request"
            assert params["method"] == "POST"
            assert params["body"] == {"$bytes": "aGVsbG8="}
            result = {"status": 200, "body": "ok"}
        await _write(writer, _response(request, result=result))

    socket_path, server = await _start_broker(tmp_path, handler)

    async def forbidden_sdk_fallback(*_args, **_kwargs):
        raise AssertionError("Slack SDK closed-session fallback was used")

    def forbidden_aiohttp_session(*_args, **_kwargs):
        raise AssertionError("aiohttp Internet session was created")

    async def forbidden_af_inet(*_args, **_kwargs):
        raise AssertionError("AF_INET connection was attempted")

    monkeypatch.setattr(
        slack_async_base_client,
        "_request_with_session",
        forbidden_sdk_fallback,
    )
    monkeypatch.setattr(aiohttp, "ClientSession", forbidden_aiohttp_session)
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", forbidden_af_inet)

    try:
        client = BrokeredAsyncWebClient(_client(socket_path), workspace_id="T1")
        response = await client.chat_postMessage(channel="C1", text="hello")
        assert response["ok"] is True
        uploaded = await client.files_upload_v2(
            channel="C1", content=b"hello", filename="hello.txt"
        )
        assert uploaded["file"]["id"] == "F1"
    finally:
        server.close()
        await server.wait_closed()

    assert calls == [
        "slack.web_api",
        "slack.web_api",
        "http.request",
        "slack.web_api",
    ]


@pytest.mark.asyncio
async def test_socket_events_ack_without_aiohttp_receive_or_close_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # Characterize the pinned legacy implementation: its receive loop owns
    # aiohttp WS frames and explicitly branches on CLOSE. Brokered mode must
    # work even when that exact path is prohibited.
    assert "WSMsgType.CLOSE" in inspect.getsource(AiohttpSocketModeClient.receive_messages)

    async def forbidden_receive(*_args, **_kwargs):
        raise AssertionError("aiohttp websocket receive path was used")

    monkeypatch.setattr(aiohttp.ClientWebSocketResponse, "receive", forbidden_receive)
    acked = asyncio.Event()

    async def handler(request, reader, writer):
        await _write(writer, _response(request, result={"subscribed": True}))
        await _write(
            writer,
            {
                "version": 1,
                "type": "event",
                "profile_id": "prod",
                "envelope_id": "E1",
                "payload": {"type": "events_api", "event": {"type": "message"}},
            },
        )
        ack = json.loads(await asyncio.wait_for(reader.readline(), timeout=1))
        assert ack["type"] == "ack"
        assert ack["envelope_id"] == "E1"
        assert ack["profile_id"] == "prod"
        acked.set()

    socket_path, server = await _start_broker(tmp_path, handler)
    client = BrokerSocketModeClient(_client(socket_path), lambda _payload: _return({"ok": True}))
    task = asyncio.create_task(client.run())
    try:
        await asyncio.wait_for(acked.wait(), timeout=1)
    finally:
        await client.close()
        await asyncio.wait_for(task, timeout=1)
        server.close()
        await server.wait_closed()
    assert SupervisorState.RUNNING in client.state_history


async def _return(value: Any) -> Any:
    return value


@pytest.mark.asyncio
async def test_terminal_denial_is_exit_78_and_never_restarts(tmp_path: Path):
    connections = 0

    async def handler(request, _reader, writer):
        nonlocal connections
        connections += 1
        await _write(writer, _response(request, status="denied"))

    socket_path, server = await _start_broker(tmp_path, handler)
    client = BrokerSocketModeClient(_client(socket_path), lambda payload: _return(payload))
    try:
        with pytest.raises(BrokerTerminalDenied) as raised:
            await client.run()
    finally:
        server.close()
        await server.wait_closed()
    assert raised.value.code == 78
    assert client.state is SupervisorState.TERMINAL_DENIED
    assert client.failure_count == 0
    assert connections == 1


@pytest.mark.asyncio
async def test_adapter_reports_terminal_denial_without_restart():
    adapter = SlackAdapter(
        PlatformConfig(enabled=True, extra={"brokered_egress": True})
    )
    adapter._running = True
    adapter._set_fatal_error = Mock()
    adapter._notify_fatal_error = AsyncMock()
    task = asyncio.get_running_loop().create_future()
    adapter._socket_mode_task = task
    task.set_exception(BrokerTerminalDenied("profile denied"))

    adapter._on_socket_mode_task_done(task)
    await asyncio.sleep(0)

    adapter._set_fatal_error.assert_called_once_with(
        "broker_policy_denied", "profile denied", retryable=False
    )
    adapter._notify_fatal_error.assert_awaited_once()


@pytest.mark.asyncio
async def test_retry_count_is_monotonic_across_successful_handshakes(tmp_path: Path):
    async def handler(request, _reader, writer):
        await _write(writer, _response(request, result={"subscribed": True}))

    socket_path, server = await _start_broker(tmp_path, handler)
    client = BrokerSocketModeClient(_client(socket_path), lambda payload: _return(payload))
    task = asyncio.create_task(client.run())
    try:
        async with asyncio.timeout(1):
            while client.failure_count < 3:
                await asyncio.sleep(0)
        assert client.failure_count >= 3
        running_positions = [
            i for i, state in enumerate(client.state_history) if state is SupervisorState.RUNNING
        ]
        assert len(running_positions) >= 3
    finally:
        await client.close()
        await asyncio.wait_for(task, timeout=1)
        server.close()
        await server.wait_closed()


def test_retry_delay_stays_bounded_after_long_outage(tmp_path: Path):
    client = BrokerSocketModeClient(
        _client(tmp_path / "missing.sock"), lambda payload: _return(payload)
    )
    client.failure_count = 100_000

    assert client._retry_delay(RuntimeError("offline")) == 0.002


@pytest.mark.asyncio
async def test_profile_mismatch_is_rejected_and_never_acknowledged(tmp_path: Path):
    saw_ack = False

    async def handler(request, reader, writer):
        nonlocal saw_ack
        await _write(writer, _response(request, result={"subscribed": True}))
        await _write(
            writer,
            {
                "version": 1,
                "type": "event",
                "profile_id": "other",
                "envelope_id": "E1",
                "payload": {"type": "events_api"},
            },
        )
        try:
            saw_ack = bool(await asyncio.wait_for(reader.readline(), timeout=0.1))
        except asyncio.TimeoutError:
            pass

    socket_path, server = await _start_broker(tmp_path, handler)
    client = BrokerSocketModeClient(_client(socket_path), lambda payload: _return(payload))
    try:
        with pytest.raises(BrokerProtocolError, match="cross-profile"):
            await client.run()
    finally:
        server.close()
        await server.wait_closed()
    assert saw_ack is False


@pytest.mark.asyncio
async def test_cancelled_request_closes_unix_connection(tmp_path: Path):
    request_seen = asyncio.Event()
    peer_closed = asyncio.Event()

    async def handler(_request, reader, _writer):
        request_seen.set()
        assert await reader.readline() == b""
        peer_closed.set()

    socket_path, server = await _start_broker(tmp_path, handler)
    task = asyncio.create_task(_client(socket_path).request("stall", {}))
    try:
        await asyncio.wait_for(request_seen.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(peer_closed.wait(), timeout=1)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_response_profile_mismatch_is_rejected(tmp_path: Path):
    async def handler(request, _reader, writer):
        response = _response(request, result={})
        response["profile_id"] = "other"
        await _write(writer, response)

    socket_path, server = await _start_broker(tmp_path, handler)
    try:
        with pytest.raises(BrokerProtocolError, match="cross-profile"):
            await _client(socket_path).request("test", {})
    finally:
        server.close()
        await server.wait_closed()
