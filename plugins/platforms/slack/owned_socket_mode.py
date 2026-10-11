"""Hermes-owned Slack HTTP and Socket Mode transport boundaries."""

from __future__ import annotations

import asyncio
import json
import logging
from time import time
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import aiohttp

from hermes_cli.external_request_guard import (
    ExternalRequestBlocked,
    ExternalRequestController,
    ExternalRequestPermit,
    get_external_request_controller,
)


logger = logging.getLogger(__name__)

_HTTP_HOSTS = frozenset({"slack.com", "files.slack.com"})
_SOCKET_HOSTS = frozenset({"wss-primary.slack.com", "wss-backup.slack.com"})
_HTTP_METHODS = frozenset({"GET", "POST"})


def classify_slack_destination(method: str, url: Any) -> str:
    """Return a narrow operation label or fail before transport invocation."""
    parsed = urlsplit(str(url))
    host = (parsed.hostname or "").lower()
    method = method.upper()
    if parsed.username or parsed.password or parsed.fragment:
        raise ExternalRequestBlocked("Slack destination denied")
    if parsed.port not in (None, 443) or method not in _HTTP_METHODS:
        raise ExternalRequestBlocked("Slack destination denied")
    if parsed.scheme == "https" and host == "slack.com" and parsed.path.startswith("/api/"):
        return "slack_web_api"
    if parsed.scheme == "https" and host == "files.slack.com" and parsed.path.startswith("/"):
        return "slack_file_transfer"
    if parsed.scheme == "wss" and host in _SOCKET_HOSTS and parsed.path.startswith("/link/"):
        return "slack_socket_handshake"
    raise ExternalRequestBlocked("Slack destination denied")


def build_slack_client_middleware(
    controller: ExternalRequestController | None = None,
    classifier: Callable[[str, Any], str] = classify_slack_destination,
) -> Callable[[aiohttp.ClientRequest, Callable[..., Awaitable[aiohttp.ClientResponse]]], Awaitable[aiohttp.ClientResponse]]:
    """Authorize inside aiohttp's retry loop; traces remain observational only."""
    active_controller = controller or get_external_request_controller()

    async def middleware(
        request: aiohttp.ClientRequest,
        handler: Callable[[aiohttp.ClientRequest], Awaitable[aiohttp.ClientResponse]],
    ) -> aiohttp.ClientResponse:
        operation = classifier(request.method, request.url)
        permit = await active_controller.admit("slack_http", operation)
        terminal = "failed"
        try:
            response = await handler(request)
            await response.read()
            if 300 <= response.status < 400:
                response.release()
                raise ExternalRequestBlocked("Slack redirect denied")
            terminal = "completed"
            return response
        except asyncio.CancelledError:
            terminal = "cancelled"
            raise
        finally:
            await active_controller.complete(permit, terminal)

    return middleware


def create_guarded_slack_session(
    controller: ExternalRequestController | None = None,
) -> aiohttp.ClientSession:
    return aiohttp.ClientSession(
        middlewares=(build_slack_client_middleware(controller),),
        auto_decompress=True,
    )


class OwnedSocketModeHandler:
    """Minimal Socket Mode lifecycle owned by Hermes, not Slack's retry client."""

    def __init__(
        self,
        app: Any,
        app_token: str,
        *,
        web_client: Any,
        session: aiohttp.ClientSession,
        proxy: str | None = None,
        controller: ExternalRequestController | None = None,
        reconnect_limit: int = 20,
    ) -> None:
        self.app = app
        self.app_token = app_token
        self.web_client = web_client
        self.session = session
        self.proxy = proxy
        self.controller = controller or get_external_request_controller()
        self.reconnect_limit = reconnect_limit
        self._closed = asyncio.Event()
        self._socket: aiohttp.ClientWebSocketResponse | None = None
        self.client = self

    async def is_connected(self) -> bool:
        return self._socket is not None and not self._socket.closed

    async def start_async(self) -> None:
        failures = 0
        while not self._closed.is_set():
            try:
                await self._connect_once()
                failures = 0
            except ExternalRequestBlocked:
                raise
            except asyncio.CancelledError:
                raise
            except Exception:
                failures += 1
                if failures >= self.reconnect_limit:
                    raise
                await asyncio.sleep(min(0.25 * (2 ** min(failures, 4)), 4.0))

    async def close_async(self) -> None:
        self._closed.set()
        socket = self._socket
        self._socket = None
        if socket is not None and not socket.closed:
            async with self.controller.admission("slack_socket_control", "close"):
                await socket.close()

    async def revoke(self) -> int:
        generation = await self.controller.revoke()
        await self.close_async()
        return generation

    async def _connect_once(self) -> None:
        result = await self.web_client.apps_connections_open(app_token=self.app_token)
        socket_url = result.get("url")
        classify_slack_destination("GET", socket_url)
        async with self.session.ws_connect(
            socket_url,
            proxy=self.proxy,
            autoping=False,
            autoclose=False,
        ) as socket:
            self._socket = socket
            try:
                await self._receive(socket)
            finally:
                if self._socket is socket:
                    self._socket = None

    async def _receive(self, socket: aiohttp.ClientWebSocketResponse) -> None:
        async for message in socket:
            if message.type == aiohttp.WSMsgType.TEXT:
                await self._dispatch_text(socket, message.data)
            elif message.type == aiohttp.WSMsgType.PING:
                payload = bytes(message.data or b"")[:125]
                async with self.controller.admission("slack_socket_control", "pong"):
                    await socket.pong(payload)
            elif message.type in {
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSED,
                aiohttp.WSMsgType.ERROR,
            }:
                return

    async def _dispatch_text(
        self, socket: aiohttp.ClientWebSocketResponse, raw_message: str
    ) -> None:
        from slack_bolt.adapter.socket_mode.async_internals import run_async_bolt_app
        from slack_sdk.socket_mode.request import SocketModeRequest

        try:
            message = json.loads(raw_message)
        except (TypeError, ValueError):
            return
        request = SocketModeRequest.from_dict(message)
        if request is None:
            return
        started = time()
        response = await run_async_bolt_app(self.app, request)
        if response.status != 200:
            logger.info("Unsuccessful Bolt result for Socket Mode request")
            return
        payload: dict[str, Any] = {"envelope_id": request.envelope_id}
        if response.body:
            content_type = response.headers.get("content-type", [""])[0]
            if content_type.startswith("application/json"):
                payload["payload"] = json.loads(response.body)
            else:
                payload["payload"] = {"text": response.body}
        await self.send_application_json(socket, payload, operation="ack")
        logger.debug("Socket Mode response completed in %d ms", int((time() - started) * 1000))

    async def send_application_json(
        self,
        socket: aiohttp.ClientWebSocketResponse,
        payload: dict[str, Any],
        *,
        operation: str,
    ) -> None:
        async with self.controller.admission("slack_socket_frame", operation):
            await socket.send_json(payload)

    async def send_application_text(
        self,
        socket: aiohttp.ClientWebSocketResponse,
        payload: str,
        *,
        operation: str,
    ) -> None:
        async with self.controller.admission("slack_socket_frame", operation):
            await socket.send_str(payload)

    async def send_application_bytes(
        self,
        socket: aiohttp.ClientWebSocketResponse,
        payload: bytes,
        *,
        operation: str,
    ) -> None:
        async with self.controller.admission("slack_socket_frame", operation):
            await socket.send_bytes(payload)

    async def send_ping(
        self, socket: aiohttp.ClientWebSocketResponse, payload: bytes = b""
    ) -> None:
        if len(payload) > 125:
            raise ExternalRequestBlocked("Slack control payload denied")
        async with self.controller.admission("slack_socket_control", "ping"):
            await socket.ping(payload)

    async def send_pong(
        self, socket: aiohttp.ClientWebSocketResponse, payload: bytes = b""
    ) -> None:
        if len(payload) > 125:
            raise ExternalRequestBlocked("Slack control payload denied")
        async with self.controller.admission("slack_socket_control", "pong"):
            await socket.pong(payload)
