"""httpx transports with durable, per-wire external-request admission."""

from __future__ import annotations

import asyncio
import threading
from typing import Callable, Iterable
from urllib.parse import urlsplit

import httpx

from hermes_cli.external_request_guard import (
    ExternalRequestBlocked,
    ExternalRequestController,
    ExternalRequestPermit,
    get_external_request_controller,
)


DestinationClassifier = Callable[[str, httpx.URL], str]


def build_env_http_transport(
    base_url: str,
    *,
    async_mode: bool = False,
    verify: object = True,
    limits: httpx.Limits | None = None,
) -> httpx.BaseTransport | httpx.AsyncBaseTransport:
    """Build an explicit inner transport without losing proxy or CA env support."""
    from agent.process_bootstrap import _get_proxy_for_base_url

    transport_cls = httpx.AsyncHTTPTransport if async_mode else httpx.HTTPTransport
    return transport_cls(
        verify=verify,
        proxy=_get_proxy_for_base_url(base_url),
        limits=limits or httpx.Limits(),
        retries=0,
        trust_env=True,
    )


def build_origin_classifier(
    allowed_origins: Iterable[str],
    *,
    methods: Iterable[str],
    operation: str,
    allow_local_http: bool = False,
    exact_path: bool = False,
) -> DestinationClassifier:
    """Build an exact scheme/host/port allowlist for one operation."""
    normalized: set[tuple[str, str, int, str]] = set()
    for origin in allowed_origins:
        parsed = urlsplit(str(origin))
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if parsed.username or parsed.password or parsed.fragment or not host:
            raise ValueError("invalid guarded origin")
        if scheme != "https" and not (
            allow_local_http
            and scheme == "http"
            and host in {"127.0.0.1", "::1", "localhost"}
        ):
            raise ValueError("guarded origins require HTTPS")
        port = parsed.port or (443 if scheme == "https" else 80)
        normalized.add((scheme, host, port, parsed.path.rstrip("/") or "/"))
    allowed_methods = frozenset(str(method).upper() for method in methods)

    def classify(method: str, url: httpx.URL) -> str:
        parsed = urlsplit(str(url))
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        destination = (parsed.scheme.lower(), host, port)
        path_allowed = any(
            destination == allowed[:3]
            and (
                parsed.path == allowed[3]
                if exact_path
                else allowed[3] == "/"
                or parsed.path == allowed[3]
                or parsed.path.startswith(f"{allowed[3]}/")
            )
            for allowed in normalized
        )
        if (
            parsed.username
            or parsed.password
            or parsed.fragment
            or method.upper() not in allowed_methods
            or not path_allowed
        ):
            raise ExternalRequestBlocked("External destination denied")
        return operation

    return classify


class _Terminal:
    def __init__(
        self,
        controller: ExternalRequestController,
        permit: ExternalRequestPermit,
        *,
        lease_seconds: float,
        abandon: Callable[[], None],
    ) -> None:
        self.controller = controller
        self.permit = permit
        self._done = False
        self._lock = threading.Lock()
        self._timer = threading.Timer(lease_seconds, self._expire, args=(abandon,))
        self._timer.daemon = True
        self._timer.start()

    def finish(self, state: str) -> None:
        with self._lock:
            if self._done:
                return
            self._done = True
            self._timer.cancel()
        self.controller.complete_sync(self.permit, state)

    def _expire(self, abandon: Callable[[], None]) -> None:
        with self._lock:
            if self._done:
                return
            self._done = True
        try:
            abandon()
        finally:
            self.controller.complete_sync(self.permit, "abandoned")


class _GuardedSyncStream(httpx.SyncByteStream):
    def __init__(
        self,
        stream: httpx.SyncByteStream,
        controller: ExternalRequestController,
        permit: ExternalRequestPermit,
        lease_seconds: float,
    ) -> None:
        self._stream = stream
        self._exhausted = False
        self._terminal = _Terminal(
            controller, permit, lease_seconds=lease_seconds, abandon=self._stream.close
        )

    def __iter__(self) -> Iterable[bytes]:
        try:
            yield from self._stream
        except BaseException:
            self._terminal.finish("failed")
            raise
        else:
            self._exhausted = True
            self._terminal.finish("completed")

    def close(self) -> None:
        try:
            self._stream.close()
        finally:
            self._terminal.finish("completed" if self._exhausted else "abandoned")


class _GuardedAsyncStream(httpx.AsyncByteStream):
    def __init__(
        self,
        stream: httpx.AsyncByteStream,
        controller: ExternalRequestController,
        permit: ExternalRequestPermit,
        lease_seconds: float,
    ) -> None:
        self._stream = stream
        self._exhausted = False
        self._loop = asyncio.get_running_loop()
        self._terminal = _Terminal(
            controller,
            permit,
            lease_seconds=lease_seconds,
            abandon=lambda: self._loop.call_soon_threadsafe(
                asyncio.create_task, self._stream.aclose()
            ),
        )

    async def __aiter__(self):
        try:
            async for chunk in self._stream:
                yield chunk
        except asyncio.CancelledError:
            self._terminal.finish("cancelled")
            raise
        except BaseException:
            self._terminal.finish("failed")
            raise
        else:
            self._exhausted = True
            self._terminal.finish("completed")

    async def aclose(self) -> None:
        try:
            await self._stream.aclose()
        finally:
            self._terminal.finish("completed" if self._exhausted else "abandoned")


class GuardedHTTPTransport(httpx.BaseTransport):
    """Authorize each synchronous wire attempt before the inner transport."""

    def __init__(
        self,
        classifier: DestinationClassifier,
        *,
        request_type: str,
        controller: ExternalRequestController | None = None,
        transport: httpx.BaseTransport | None = None,
        lease_seconds: float = 300.0,
    ) -> None:
        self._classifier = classifier
        self._request_type = request_type
        self._controller = controller or get_external_request_controller()
        self._transport = transport or httpx.HTTPTransport(retries=0)
        self._lease_seconds = lease_seconds

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        operation = self._classifier(request.method, request.url)
        permit = self._controller.admit_sync(self._request_type, operation)
        try:
            response = self._controller.egress_sync(
                permit, lambda: self._transport.handle_request(request)
            )
            if response.is_redirect:
                response.close()
                raise ExternalRequestBlocked("Redirect denied before follow-up egress")
        except BaseException:
            self._controller.complete_sync(permit, "failed")
            raise
        response.stream = _GuardedSyncStream(
            response.stream, self._controller, permit, self._lease_seconds
        )
        return response

    def close(self) -> None:
        self._transport.close()


class GuardedAsyncHTTPTransport(httpx.AsyncBaseTransport):
    """Authorize each asynchronous wire attempt before the inner transport."""

    def __init__(
        self,
        classifier: DestinationClassifier,
        *,
        request_type: str,
        controller: ExternalRequestController | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        lease_seconds: float = 300.0,
    ) -> None:
        self._classifier = classifier
        self._request_type = request_type
        self._controller = controller or get_external_request_controller()
        self._transport = transport or httpx.AsyncHTTPTransport(retries=0)
        self._lease_seconds = lease_seconds

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        operation = self._classifier(request.method, request.url)
        permit = await self._controller.admit(self._request_type, operation)
        try:
            response = await self._controller.egress(
                permit, lambda: self._transport.handle_async_request(request)
            )
            if response.is_redirect:
                await response.aclose()
                raise ExternalRequestBlocked("Redirect denied before follow-up egress")
        except asyncio.CancelledError:
            await self._controller.complete(permit, "cancelled")
            raise
        except BaseException:
            await self._controller.complete(permit, "failed")
            raise
        response.stream = _GuardedAsyncStream(
            response.stream, self._controller, permit, self._lease_seconds
        )
        return response

    async def aclose(self) -> None:
        await self._transport.aclose()
