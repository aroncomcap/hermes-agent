"""Credential-free Slack transport over a local Unix broker.

The gateway side of brokered egress never receives a Slack credential and never
opens an Internet socket.  The companion broker owns Slack Web API and Socket
Mode connections and exposes a small, profile-scoped JSON-lines protocol over a
Unix socket.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Mapping, Optional, Union

from aiohttp import FormData
from slack_bolt.async_app import AsyncApp
from slack_bolt.authorization.authorize_result import AuthorizeResult
from slack_bolt.request.async_request import AsyncBoltRequest
from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.web.async_slack_response import AsyncSlackResponse
from slack_sdk.web.file_upload_v2_result import FileUploadV2Result

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = 1
EX_CONFIG = 78
MAX_FRAME_BYTES = 8 * 1024 * 1024
_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class BrokerProtocolError(RuntimeError):
    """The local broker violated the IPC contract."""


class BrokerRetryableError(RuntimeError):
    """The broker is temporarily unavailable or asked the client to retry."""

    def __init__(self, message: str, *, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class BrokerTerminalDenied(SystemExit):
    """Terminal broker policy denial; maps to systemd-safe EX_CONFIG (78)."""

    def __init__(self, message: str):
        super().__init__(EX_CONFIG)
        self.reason = message

    def __str__(self) -> str:
        return self.reason


class SupervisorState(str, Enum):
    DISABLED = "disabled"
    CONNECTING = "connecting"
    RUNNING = "running"
    RETRY_WAIT = "retry_wait"
    TERMINAL_DENIED = "terminal_denied"
    STOPPED = "stopped"


@dataclass(frozen=True)
class BrokerSettings:
    socket_path: Path
    profile_id: str
    connect_timeout: float = 5.0
    request_timeout: float = 30.0
    retry_base: float = 0.5
    retry_cap: float = 30.0

    def __post_init__(self) -> None:
        if not self.socket_path.is_absolute():
            raise ValueError("broker socket path must be absolute")
        if not _PROFILE_RE.fullmatch(self.profile_id):
            raise ValueError("invalid broker profile identifier")


def default_broker_socket_path() -> Path:
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir:
        return Path(runtime_dir) / "hermes-egress-broker.sock"
    return Path("/run/hermes-egress/broker.sock")


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {"$bytes": base64.b64encode(value).decode("ascii")}
    if isinstance(value, Path):
        return {"$path": str(value)}
    if hasattr(value, "read"):
        data = value.read()
        if isinstance(data, str):
            data = data.encode()
        return {
            "$bytes": base64.b64encode(data).decode("ascii"),
            "filename": getattr(value, "name", None),
        }
    if isinstance(value, Mapping):
        return {str(k): _json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(v) for v in value]
    raise TypeError(f"unsupported broker payload type: {type(value).__name__}")


def decode_bytes(value: Any) -> bytes:
    if not isinstance(value, Mapping) or set(value) != {"$bytes"}:
        raise BrokerProtocolError("broker response did not contain encoded bytes")
    try:
        return base64.b64decode(str(value["$bytes"]), validate=True)
    except Exception as exc:
        raise BrokerProtocolError("broker returned invalid base64 bytes") from exc


class BrokerIPCClient:
    """One-request-per-connection Unix IPC client.

    Short-lived request connections make cancellation and response correlation
    unambiguous.  Socket Mode uses a separate long-lived connection below.
    """

    def __init__(self, settings: BrokerSettings):
        self.settings = settings

    def _request(self, operation: str, params: Mapping[str, Any]) -> dict[str, Any]:
        request_id = f"{self.settings.profile_id}:{uuid.uuid4().hex}"
        return {
            "version": PROTOCOL_VERSION,
            "type": "request",
            "profile_id": self.settings.profile_id,
            "request_id": request_id,
            "operation": operation,
            "params": _json_value(params),
        }

    async def _open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            return await asyncio.wait_for(
                asyncio.open_unix_connection(
                    str(self.settings.socket_path), limit=MAX_FRAME_BYTES
                ),
                timeout=self.settings.connect_timeout,
            )
        except asyncio.CancelledError:
            raise
        except (OSError, asyncio.TimeoutError) as exc:
            raise BrokerRetryableError(f"cannot connect to egress broker: {exc}") from exc

    @staticmethod
    async def _close(writer: Optional[asyncio.StreamWriter]) -> None:
        if writer is None:
            return
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.shield(writer.wait_closed())

    async def request(self, operation: str, params: Mapping[str, Any]) -> Any:
        frame = self._request(operation, params)
        reader: Optional[asyncio.StreamReader] = None
        writer: Optional[asyncio.StreamWriter] = None
        try:
            reader, writer = await self._open()
            writer.write(json.dumps(frame, separators=(",", ":")).encode() + b"\n")
            await writer.drain()
            raw = await asyncio.wait_for(
                reader.readline(), timeout=self.settings.request_timeout
            )
            if not raw:
                raise BrokerRetryableError("egress broker closed without a response")
            response = self._parse_response(raw, frame["request_id"])
            return self._unwrap(response)
        except asyncio.CancelledError:
            raise
        finally:
            await self._close(writer)

    def _parse_response(self, raw: bytes, request_id: str) -> dict[str, Any]:
        if len(raw) > MAX_FRAME_BYTES:
            raise BrokerProtocolError("broker response exceeded frame limit")
        try:
            response = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrokerProtocolError("broker returned malformed JSON") from exc
        if not isinstance(response, dict) or response.get("type") != "response":
            raise BrokerProtocolError("broker returned an invalid response frame")
        if response.get("version") != PROTOCOL_VERSION:
            raise BrokerProtocolError("broker protocol version mismatch")
        if response.get("profile_id") != self.settings.profile_id:
            raise BrokerProtocolError("cross-profile broker response rejected")
        if response.get("request_id") != request_id:
            raise BrokerProtocolError("broker response correlation mismatch")
        return response

    @staticmethod
    def _unwrap(response: Mapping[str, Any]) -> Any:
        status = response.get("status")
        if status == "ok":
            return response.get("result")
        message = str(response.get("error") or "egress broker request failed")
        if status == "denied":
            raise BrokerTerminalDenied(message)
        if status == "retry":
            retry_after = response.get("retry_after")
            raise BrokerRetryableError(
                message,
                retry_after=float(retry_after) if retry_after is not None else None,
            )
        raise BrokerProtocolError(f"unknown broker response status: {status!r}")

    async def slack_auth_list(self) -> list[dict[str, Any]]:
        result = await self.request("slack.auth_list", {})
        if not isinstance(result, list) or not result:
            raise BrokerProtocolError("broker returned no Slack workspace identities")
        if not all(isinstance(item, dict) for item in result):
            raise BrokerProtocolError("broker returned invalid Slack workspace identities")
        return result

    async def http_request(
        self,
        *,
        method: str,
        url: str,
        json_body: Any = None,
        body: Any = None,
        workspace_id: Optional[str] = None,
        slack_authorized: bool = False,
    ) -> dict[str, Any]:
        result = await self.request(
            "http.request",
            {
                "method": method,
                "url": url,
                "json": json_body,
                "body": body,
                "workspace_id": workspace_id,
                "slack_authorized": slack_authorized,
            },
        )
        if not isinstance(result, dict):
            raise BrokerProtocolError("broker returned invalid HTTP response")
        return result


class BrokeredAsyncWebClient(AsyncWebClient):
    """Slack SDK-compatible client whose only transport is Unix IPC."""

    def __init__(
        self, broker: BrokerIPCClient, *, workspace_id: Optional[str] = None
    ) -> None:
        super().__init__(token=None)
        self._broker = broker
        self.workspace_id = workspace_id

    async def api_call(
        self,
        api_method: str,
        *,
        http_verb: str = "POST",
        files: Optional[dict] = None,
        data: Optional[Union[dict, FormData]] = None,
        params: Optional[dict] = None,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
        auth: Optional[dict] = None,
    ) -> AsyncSlackResponse:
        result = await self._broker.request(
            "slack.web_api",
            {
                "workspace_id": self.workspace_id,
                "api_method": api_method,
                "http_verb": http_verb,
                "files": files,
                "data": data,
                "params": params,
                "json": json,
                "headers": headers,
                "auth": auth,
            },
        )
        if not isinstance(result, dict):
            raise BrokerProtocolError("broker returned invalid Slack Web API response")
        if "data" in result and isinstance(result["data"], dict):
            body = result["data"]
            status_code = int(result.get("status_code", 200))
            response_headers = result.get("headers") or {}
        else:
            body = result
            status_code = 200
            response_headers = {}
        return AsyncSlackResponse(
            client=self,
            http_verb=http_verb,
            api_url=f"broker://slack/{api_method}",
            req_args={},
            data=body,
            headers=response_headers,
            status_code=status_code,
        )

    async def _upload_file(
        self,
        *,
        url: str,
        data: bytes,
        logger: logging.Logger,
        timeout: int,
        proxy: Optional[str],
        ssl: Any,
    ) -> FileUploadV2Result:
        """Complete Slack SDK upload-v2 step 2 through the broker.

        The pinned SDK normally calls ``_request_with_session`` here, including
        its closed-session fallback that creates a new aiohttp session.  That
        path is forbidden in brokered mode because it would give the gateway
        direct AF_INET ownership.
        """
        del logger, timeout, proxy, ssl
        result = await self._broker.http_request(
            method="POST",
            url=url,
            body=data,
            workspace_id=self.workspace_id,
        )
        return FileUploadV2Result(
            status=int(result.get("status", 0)),
            body=result.get("body", b""),
        )


class BrokeredAsyncApp(AsyncApp):
    """Bolt app that preserves the brokered client for every request context.

    Pinned Bolt creates a plain ``AsyncWebClient`` inside ``_init_context`` even
    when the application was constructed with a subclass.  Replacing that
    per-request client is part of the egress boundary: listeners, ``say()``,
    and middleware must never regain Slack SDK's Internet transport.
    """

    def __init__(
        self, broker: BrokerIPCClient, identities: list[Mapping[str, Any]]
    ) -> None:
        if not identities:
            raise BrokerProtocolError("broker returned no Slack identities")
        self._broker = broker
        self._identities: dict[str, Mapping[str, Any]] = {}
        for identity in identities:
            team_id = str(identity.get("team_id") or "")
            if not team_id:
                raise BrokerProtocolError(
                    "broker returned Slack identity without team_id"
                )
            self._identities[team_id] = identity
        self._primary_team_id = next(iter(self._identities))
        self._brokered_clients = {
            team_id: BrokeredAsyncWebClient(broker, workspace_id=team_id)
            for team_id in self._identities
        }

        async def authorize(
            *,
            context: Any,
            enterprise_id: Optional[str],
            team_id: Optional[str],
            user_id: Optional[str],
            **_kwargs: Any,
        ) -> Optional[AuthorizeResult]:
            del context, enterprise_id
            selected_team = team_id or self._primary_team_id
            identity = self._identities.get(selected_team)
            if identity is None:
                return None
            return AuthorizeResult(
                enterprise_id=identity.get("enterprise_id"),
                team_id=selected_team,
                team=identity.get("team"),
                bot_user_id=identity.get("user_id"),
                bot_id=identity.get("bot_id"),
                user_id=user_id,
            )

        # The non-secret sentinel prevents Bolt from consulting SLACK_BOT_TOKEN.
        # Because an explicit client is supplied, Bolt immediately replaces its
        # internal token with the client's None value and uses ``authorize``.
        super().__init__(
            token="brokered-no-credential",
            client=self._brokered_clients[self._primary_team_id],
            authorize=authorize,
            signing_secret="brokered-no-secret",
            verification_token="brokered-no-token",
            request_verification_enabled=False,
        )

    def _init_context(self, req: AsyncBoltRequest) -> None:
        super()._init_context(req)
        team_id = req.context.team_id or self._primary_team_id
        req.context["client"] = self._brokered_clients.get(
            team_id, BrokeredAsyncWebClient(self._broker, workspace_id=team_id)
        )


class BrokerSocketModeClient:
    """Profile-isolated Socket Mode event/ACK channel with bounded retry."""

    def __init__(
        self,
        broker: BrokerIPCClient,
        dispatch: Callable[[dict[str, Any]], Awaitable[Any]],
    ) -> None:
        self.broker = broker
        self.dispatch = dispatch
        self.state = SupervisorState.STOPPED
        self.state_history: list[SupervisorState] = [self.state]
        self.failure_count = 0
        self.is_connected = False
        self._stop = asyncio.Event()
        self._writer: Optional[asyncio.StreamWriter] = None
        self._write_lock = asyncio.Lock()

    def _transition(self, state: SupervisorState) -> None:
        self.state = state
        self.state_history.append(state)

    def _retry_delay(self, exc: BaseException) -> float:
        requested = getattr(exc, "retry_after", None)
        if requested is None:
            # failure_count is intentionally monotonic, so cap the exponent as
            # well as the final delay to avoid giant integers on long outages.
            exponent = min(max(self.failure_count - 1, 0), 30)
            requested = self.broker.settings.retry_base * (2**exponent)
        return min(
            self.broker.settings.retry_cap,
            max(0.0, float(requested)),
        )

    async def close(self) -> None:
        self._stop.set()
        self.is_connected = False
        await self.broker._close(self._writer)
        self._writer = None
        if self.state is not SupervisorState.TERMINAL_DENIED:
            self._transition(SupervisorState.STOPPED)

    async def run(self) -> None:
        while not self._stop.is_set():
            self._transition(SupervisorState.CONNECTING)
            try:
                await self._run_once()
                if self._stop.is_set():
                    break
                raise BrokerRetryableError("broker event stream ended")
            except asyncio.CancelledError:
                raise
            except BrokerTerminalDenied:
                self.is_connected = False
                self._transition(SupervisorState.TERMINAL_DENIED)
                raise
            except (BrokerRetryableError, OSError, asyncio.TimeoutError) as exc:
                self.is_connected = False
                self.failure_count += 1
                self._transition(SupervisorState.RETRY_WAIT)
                delay = self._retry_delay(exc)
                logger.warning(
                    "[Slack] Broker event stream unavailable; retry %d in %.1fs: %s",
                    self.failure_count,
                    delay,
                    exc,
                )
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                except asyncio.TimeoutError:
                    pass
            finally:
                self.is_connected = False
                await self.broker._close(self._writer)
                self._writer = None
        if self.state is not SupervisorState.TERMINAL_DENIED:
            self._transition(SupervisorState.STOPPED)

    async def _run_once(self) -> None:
        reader, writer = await self.broker._open()
        self._writer = writer
        request = self.broker._request("slack.events", {})
        writer.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        await writer.drain()
        raw = await asyncio.wait_for(
            reader.readline(), timeout=self.broker.settings.request_timeout
        )
        response = self.broker._parse_response(raw, request["request_id"])
        self.broker._unwrap(response)
        self.is_connected = True
        self._transition(SupervisorState.RUNNING)
        while not self._stop.is_set():
            raw = await reader.readline()
            if not raw:
                return
            frame = self._parse_event(raw)
            ack_payload = await self.dispatch(frame["payload"])
            await self._send_ack(frame["envelope_id"], ack_payload)

    def _parse_event(self, raw: bytes) -> dict[str, Any]:
        if len(raw) > MAX_FRAME_BYTES:
            raise BrokerProtocolError("broker event exceeded frame limit")
        try:
            frame = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrokerProtocolError("broker returned malformed event JSON") from exc
        if not isinstance(frame, dict) or frame.get("type") != "event":
            raise BrokerProtocolError("broker returned an invalid event frame")
        if frame.get("version") != PROTOCOL_VERSION:
            raise BrokerProtocolError("broker event protocol version mismatch")
        if frame.get("profile_id") != self.broker.settings.profile_id:
            raise BrokerProtocolError("cross-profile broker event rejected")
        if not frame.get("envelope_id") or not isinstance(frame.get("payload"), dict):
            raise BrokerProtocolError("broker event missing envelope or payload")
        return frame

    async def _send_ack(self, envelope_id: str, payload: Any) -> None:
        writer = self._writer
        if writer is None:
            raise BrokerRetryableError("broker event stream closed before ACK")
        frame = {
            "version": PROTOCOL_VERSION,
            "type": "ack",
            "profile_id": self.broker.settings.profile_id,
            "envelope_id": envelope_id,
            "payload": _json_value(payload),
        }
        async with self._write_lock:
            writer.write(json.dumps(frame, separators=(",", ":")).encode() + b"\n")
            await writer.drain()


class BrokeredSocketModeHandler:
    """Small handler facade matching the adapter's legacy handler lifecycle."""

    def __init__(self, app: Any, broker: BrokerIPCClient):
        self.app = app
        self.client = BrokerSocketModeClient(broker, self._dispatch)

    async def _dispatch(self, payload: dict[str, Any]) -> Any:
        request = AsyncBoltRequest(body=json.dumps(payload), mode="socket_mode")
        response = await self.app.async_dispatch(request)
        body = getattr(response, "body", None)
        return body if body not in (None, "") else None

    async def start_async(self) -> None:
        await self.client.run()

    async def close_async(self) -> None:
        await self.client.close()
