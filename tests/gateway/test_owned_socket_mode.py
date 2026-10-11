from __future__ import annotations

import asyncio
import importlib.metadata
import sqlite3
import sys
from types import SimpleNamespace

import pytest

try:
    importlib.metadata.version("slack_sdk")
except importlib.metadata.PackageNotFoundError:
    pytest.skip("requires the optional hermes-agent[slack] extra", allow_module_level=True)

import aiohttp
from aiohttp import web
import pytest_asyncio

for _name in tuple(sys.modules):
    if _name == "slack_sdk" or _name.startswith("slack_sdk."):
        if not getattr(sys.modules[_name], "__file__", None):
            sys.modules.pop(_name, None)

from slack_sdk.http_retry.builtin_async_handlers import AsyncRateLimitErrorRetryHandler
from slack_sdk.web.async_client import AsyncWebClient

from hermes_cli.external_request_guard import ExternalRequestBlocked, ExternalRequestController
from plugins.platforms.slack.owned_socket_mode import (
    OwnedSocketModeHandler,
    build_slack_client_middleware,
    classify_slack_destination,
)


@pytest_asyncio.fixture
async def local_server(unused_tcp_port):
    observed = {"root": 0, "target": 0, "frames": [], "retry": 0}

    async def root(request):
        observed["root"] += 1
        return web.Response(text="ok")

    async def redirect(request):
        observed["root"] += 1
        raise web.HTTPFound("/target")

    async def target(request):
        observed["target"] += 1
        return web.Response(text="unexpected")

    async def retry(request):
        observed["retry"] += 1
        if observed["retry"] == 1:
            return web.json_response(
                {"ok": False, "error": "ratelimited"},
                status=429,
                headers={"Retry-After": "0"},
            )
        return web.json_response({"ok": True, "user_id": "U1"})

    async def websocket(request):
        socket = web.WebSocketResponse(autoping=False)
        await socket.prepare(request)
        async for message in socket:
            if message.type == aiohttp.WSMsgType.TEXT:
                observed["frames"].append(("text", message.data))
            elif message.type == aiohttp.WSMsgType.BINARY:
                observed["frames"].append(("binary", bytes(message.data)))
            if len(observed["frames"]) >= 3:
                break
        return socket

    app = web.Application()
    app.router.add_get("/", root)
    app.router.add_get("/redirect", redirect)
    app.router.add_get("/target", target)
    app.router.add_post("/api/auth.test", retry)
    app.router.add_get("/ws", websocket)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", unused_tcp_port)
    await site.start()
    try:
        yield f"http://127.0.0.1:{unused_tcp_port}", observed
    finally:
        await runner.cleanup()


def test_destination_policy_is_exact():
    assert classify_slack_destination("POST", "https://slack.com/api/chat.postMessage") == "slack_web_api"
    assert classify_slack_destination("POST", "https://files.slack.com/upload/v1/abc") == "slack_file_transfer"
    assert classify_slack_destination("GET", "wss://wss-primary.slack.com/link/?ticket=x") == "slack_socket_handshake"
    for url in (
        "http://slack.com/api/auth.test",
        "https://evil-slack.com/api/auth.test",
        "https://slack.com.evil.test/api/auth.test",
        "wss://wss-primary.slack.com.evil.test/link/",
    ):
        with pytest.raises(ExternalRequestBlocked):
            classify_slack_destination("POST", url)


@pytest.mark.asyncio
async def test_http_attempts_are_distinct_and_redirect_stops_before_target(tmp_path, local_server):
    base_url, observed = local_server
    journal = tmp_path / "requests.sqlite3"
    controller = ExternalRequestController(journal)
    middleware = build_slack_client_middleware(
        controller, classifier=lambda method, url: "local_test"
    )
    async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
        async with session.get(f"{base_url}/") as response:
            assert await response.text() == "ok"
        with pytest.raises(ExternalRequestBlocked, match="redirect"):
            await session.get(f"{base_url}/redirect")

    with sqlite3.connect(journal) as connection:
        rows = connection.execute(
            "SELECT state FROM external_request_attempts ORDER BY admitted_at"
        ).fetchall()
    assert rows == [("completed",), ("failed",)]
    assert observed == {"root": 2, "target": 0, "frames": [], "retry": 0}


@pytest.mark.asyncio
async def test_pinned_slack_sdk_retry_gets_a_distinct_permit(tmp_path, local_server):
    base_url, observed = local_server
    journal = tmp_path / "requests.sqlite3"
    controller = ExternalRequestController(journal)
    middleware = build_slack_client_middleware(
        controller, classifier=lambda method, url: "local_slack_sdk"
    )
    async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
        client = AsyncWebClient(
            token="xoxb-test",
            base_url=f"{base_url}/api/",
            session=session,
            retry_handlers=[AsyncRateLimitErrorRetryHandler(max_retry_count=1)],
        )
        response = await client.auth_test()
        assert response["ok"] is True

    with sqlite3.connect(journal) as connection:
        attempts = connection.execute(
            "SELECT request_id, state FROM external_request_attempts ORDER BY admitted_at"
        ).fetchall()
    assert len({request_id for request_id, _state in attempts}) == 2
    assert [state for _request_id, state in attempts] == ["completed", "completed"]
    assert observed["retry"] == 2


@pytest.mark.asyncio
async def test_socket_application_ack_has_durable_permit(tmp_path, local_server):
    base_url, observed = local_server
    journal = tmp_path / "requests.sqlite3"
    controller = ExternalRequestController(journal)
    middleware = build_slack_client_middleware(
        controller, classifier=lambda method, url: "local_socket"
    )
    async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
        async with session.ws_connect(base_url.replace("http://", "ws://") + "/ws") as socket:
            handler = OwnedSocketModeHandler(
                SimpleNamespace(),
                "xapp-test",
                web_client=SimpleNamespace(),
                session=session,
                controller=controller,
            )
            await handler.send_application_json(socket, {"envelope_id": "E1"}, operation="ack")
            await handler.send_application_text(socket, "hello", operation="text")
            await handler.send_application_bytes(socket, b"world", operation="binary")
            await asyncio.sleep(0)

    with sqlite3.connect(journal) as connection:
        operations = connection.execute(
            "SELECT request_type, operation, state FROM external_request_attempts ORDER BY admitted_at"
        ).fetchall()
    assert ("slack_socket_frame", "ack", "completed") in operations
    assert ("slack_socket_frame", "text", "completed") in operations
    assert ("slack_socket_frame", "binary", "completed") in operations
    assert observed["frames"] == [
        ("text", '{"envelope_id": "E1"}'),
        ("text", "hello"),
        ("binary", b"world"),
    ]


@pytest.mark.asyncio
async def test_owned_socket_closes_explicitly_through_guard(tmp_path):
    journal = tmp_path / "requests.sqlite3"
    controller = ExternalRequestController(journal)

    class FakeSocket:
        closed = False
        close_calls = 0

        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

        async def close(self):
            self.close_calls += 1
            self.closed = True

    socket = FakeSocket()

    class FakeSession:
        async def ws_connect(self, *_args, **_kwargs):
            return socket

    class FakeWebClient:
        async def apps_connections_open(self, **_kwargs):
            return {"url": "wss://wss-primary.slack.com/link/?ticket=test"}

    handler = OwnedSocketModeHandler(
        SimpleNamespace(),
        "xapp-test",
        web_client=FakeWebClient(),
        session=FakeSession(),
        controller=controller,
    )

    await handler._connect_once()

    assert socket.close_calls == 1
    with sqlite3.connect(journal) as connection:
        operations = connection.execute(
            "SELECT request_type, operation, state FROM external_request_attempts"
        ).fetchall()
    assert operations == [("slack_socket_control", "close", "completed")]


@pytest.mark.asyncio
async def test_clean_disconnects_exhaust_bounded_reconnect_budget(tmp_path, monkeypatch):
    controller = ExternalRequestController(tmp_path / "requests.sqlite3")
    handler = OwnedSocketModeHandler(
        SimpleNamespace(),
        "xapp-test",
        web_client=SimpleNamespace(),
        session=SimpleNamespace(),
        controller=controller,
        reconnect_limit=3,
    )
    attempts = 0

    async def clean_disconnect():
        nonlocal attempts
        attempts += 1

    async def no_sleep(_delay):
        return None

    monkeypatch.setattr(handler, "_connect_once", clean_disconnect)
    monkeypatch.setattr(
        "plugins.platforms.slack.owned_socket_mode.asyncio.sleep", no_sleep
    )

    with pytest.raises(ConnectionError, match="reconnect limit"):
        await handler.start_async()
    assert attempts == 3


@pytest.mark.asyncio
async def test_slow_dispatch_does_not_starve_ping_control(tmp_path, monkeypatch):
    controller = ExternalRequestController(tmp_path / "requests.sqlite3")
    handler = OwnedSocketModeHandler(
        SimpleNamespace(),
        "xapp-test",
        web_client=SimpleNamespace(),
        session=SimpleNamespace(),
        controller=controller,
    )
    release_dispatch = asyncio.Event()
    pong_payloads = []

    async def slow_dispatch(_socket, _message):
        await release_dispatch.wait()

    class FakeSocket:
        closed = False

        def __init__(self):
            self._messages = iter(
                [
                    SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data="{}"),
                    SimpleNamespace(type=aiohttp.WSMsgType.PING, data=b"probe"),
                    SimpleNamespace(type=aiohttp.WSMsgType.CLOSED, data=None),
                ]
            )

        def __aiter__(self):
            return self

        async def __anext__(self):
            try:
                return next(self._messages)
            except StopIteration:
                raise StopAsyncIteration

        async def pong(self, payload):
            pong_payloads.append(payload)

    monkeypatch.setattr(handler, "_dispatch_text", slow_dispatch)
    socket = FakeSocket()

    await handler._receive(socket)

    assert pong_payloads == [b"probe"]
    assert len(handler._dispatch_tasks) == 1
    release_dispatch.set()
    await handler._cancel_dispatches()
