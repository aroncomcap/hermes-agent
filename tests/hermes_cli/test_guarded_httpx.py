from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sqlite3
import threading

import httpx
import pytest

from hermes_cli.external_request_guard import (
    ExternalRequestBlocked,
    ExternalRequestController,
)
from hermes_cli.guarded_httpx import (
    GuardedAsyncHTTPTransport,
    GuardedHTTPTransport,
    build_env_http_transport,
    build_origin_classifier,
)
from hermes_cli.plugins import get_plugin_manager


class _Handler(BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_POST(self):
        type(self).hits.append(self.path)
        redirects = {
            "/redirect-relative": "/target",
            "/redirect-same": f"http://127.0.0.1:{self.server.server_port}/target",
            "/redirect-cross": "https://example.invalid/target",
            "/redirect-downgrade": "http://example.invalid/target",
            "/redirect-malformed": "http://[::1",
        }
        if self.path in redirects:
            self.send_response(307)
            self.send_header("Location", redirects[self.path])
            self.end_headers()
            return
        body = b"guarded"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@pytest.fixture(autouse=True)
def isolated_hooks():
    manager = get_plugin_manager()
    previous = dict(manager._hooks)
    manager._hooks = {}
    try:
        yield
    finally:
        manager._hooks = previous


@pytest.fixture
def local_server():
    _Handler.hits = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def _states(path):
    with sqlite3.connect(path) as connection:
        return connection.execute(
            "SELECT state FROM external_request_attempts ORDER BY admitted_at"
        ).fetchall()


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost:11434/v1",
        "http://127.0.0.1:11434/v1",
        "http://[::1]:11434/v1",
    ],
)
def test_origin_classifier_allows_exact_loopback_http(origin):
    classifier = build_origin_classifier(
        [origin], methods={"POST"}, operation="model_inference", allow_local_http=True
    )

    assert classifier("POST", httpx.URL(f"{origin}/chat")) == "model_inference"


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.com/v1",
        "http://192.168.1.10:11434/v1",
        "http://localhost.evil.example/v1",
    ],
)
def test_origin_classifier_rejects_non_loopback_http(origin):
    with pytest.raises(ValueError, match="require HTTPS"):
        build_origin_classifier(
            [origin],
            methods={"POST"},
            operation="model_inference",
            allow_local_http=True,
        )


def test_sync_wire_attempt_completes_once(tmp_path, local_server):
    journal = tmp_path / "requests.sqlite3"
    controller = ExternalRequestController(journal)
    classifier = build_origin_classifier(
        [local_server], methods={"POST"}, operation="test", allow_local_http=True
    )
    transport = GuardedHTTPTransport(
        classifier,
        request_type="model_inference",
        controller=controller,
        transport=httpx.HTTPTransport(retries=0),
    )

    with httpx.Client(transport=transport) as client:
        response = client.post(f"{local_server}/ok")

    assert response.content == b"guarded"
    assert _Handler.hits == ["/ok"]
    assert _states(journal) == [("completed",)]


@pytest.mark.parametrize(
    "path",
    [
        "/redirect-relative",
        "/redirect-same",
        "/redirect-cross",
        "/redirect-downgrade",
        "/redirect-malformed",
    ],
)
def test_redirect_is_denied_before_second_send(tmp_path, local_server, path):
    journal = tmp_path / "requests.sqlite3"
    controller = ExternalRequestController(journal)
    classifier = build_origin_classifier(
        [local_server], methods={"POST"}, operation="test", allow_local_http=True
    )
    transport = GuardedHTTPTransport(
        classifier,
        request_type="oauth_refresh",
        controller=controller,
        transport=httpx.HTTPTransport(retries=0),
    )

    with httpx.Client(transport=transport, follow_redirects=True) as client:
        with pytest.raises(ExternalRequestBlocked, match="Redirect denied"):
            client.post(f"{local_server}{path}")

    assert _Handler.hits == [path]
    assert _states(journal) == [("failed",)]


@pytest.mark.asyncio
async def test_async_wire_attempt_completes_once(tmp_path, local_server):
    journal = tmp_path / "requests.sqlite3"
    controller = ExternalRequestController(journal)
    classifier = build_origin_classifier(
        [local_server], methods={"POST"}, operation="test", allow_local_http=True
    )
    transport = GuardedAsyncHTTPTransport(
        classifier,
        request_type="model_inference",
        controller=controller,
        transport=httpx.AsyncHTTPTransport(retries=0),
    )

    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post(f"{local_server}/ok")

    assert response.content == b"guarded"
    assert _Handler.hits == ["/ok"]
    assert _states(journal) == [("completed",)]


def test_cross_origin_and_method_are_denied_without_wire_attempt(
    tmp_path, local_server
):
    journal = tmp_path / "requests.sqlite3"
    controller = ExternalRequestController(journal)
    classifier = build_origin_classifier(
        [local_server], methods={"POST"}, operation="test", allow_local_http=True
    )
    transport = GuardedHTTPTransport(
        classifier,
        request_type="oauth_refresh",
        controller=controller,
        transport=httpx.HTTPTransport(retries=0),
    )

    with httpx.Client(transport=transport) as client:
        with pytest.raises(ExternalRequestBlocked, match="destination denied"):
            client.get(f"{local_server}/ok")
        with pytest.raises(ExternalRequestBlocked, match="destination denied"):
            client.post("http://localhost:1/target")

    assert _Handler.hits == []
    assert not journal.exists()


def test_exact_path_classifier_rejects_same_origin_path(local_server):
    classifier = build_origin_classifier(
        [f"{local_server}/token"],
        methods={"POST"},
        operation="oauth_refresh",
        allow_local_http=True,
        exact_path=True,
    )

    assert classifier("POST", httpx.URL(f"{local_server}/token")) == "oauth_refresh"
    with pytest.raises(ExternalRequestBlocked, match="destination denied"):
        classifier("POST", httpx.URL(f"{local_server}/other"))


def test_env_transport_preserves_explicit_proxy_and_ca_settings(monkeypatch):
    captured = {}
    marker = object()

    monkeypatch.setattr(
        "agent.process_bootstrap._get_proxy_for_base_url",
        lambda _base_url: "http://proxy.internal:8080",
    )

    def build_transport(**kwargs):
        captured.update(kwargs)
        return marker

    monkeypatch.setattr(httpx, "HTTPTransport", build_transport)

    assert build_env_http_transport("https://api.openai.com", verify="custom-ca.pem") is marker
    assert captured["proxy"] == "http://proxy.internal:8080"
    assert captured["verify"] == "custom-ca.pem"
    assert captured["trust_env"] is True
    assert captured["retries"] == 0
