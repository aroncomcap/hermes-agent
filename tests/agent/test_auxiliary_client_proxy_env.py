"""Regression guard: auxiliary OpenAI clients must use env-only proxy policy.

On macOS, httpx with default ``trust_env=True`` reads system proxy settings
via ``urllib.request.getproxies()`` but not the macOS proxy exception list.
Auxiliary clients (vision, title generation, etc.) must mirror the main
agent: explicit ``HTTPS_PROXY`` / ``NO_PROXY`` env vars only, via a custom
keepalive transport that suppresses automatic system-proxy detection.
"""
from unittest.mock import patch

import httpx

from agent.auxiliary_client import _create_openai_client, _openai_http_client_kwargs
from agent.process_bootstrap import _get_proxy_for_base_url


def _pool_types(http_client) -> list:
    """Return pool types through httpx mounts and Hermes transport wrappers."""
    pool_types = []
    pending = [http_client._transport, *http_client._mounts.values()]
    seen = set()
    while pending:
        transport = pending.pop()
        if transport is None or id(transport) in seen:
            continue
        seen.add(id(transport))
        pool = getattr(transport, "_pool", None)
        if pool is not None:
            pool_types.append(type(pool).__name__)
        inner = getattr(transport, "_transport", None)
        if inner is not None:
            pending.append(inner)
    return pool_types


@patch("agent.auxiliary_client.OpenAI")
def test_create_openai_client_routes_via_env_proxy(mock_openai, monkeypatch):
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
                "https_proxy", "http_proxy", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:7897")

    _create_openai_client(
        api_key="test-key",
        base_url="https://litellm.internal.example.com/v1",
    )

    http_client = mock_openai.call_args.kwargs.get("http_client")
    assert isinstance(http_client, httpx.Client)
    assert "HTTPProxy" in _pool_types(http_client)
    http_client.close()


@patch("agent.auxiliary_client.OpenAI")
def test_create_openai_client_no_proxy_when_env_unset(mock_openai, monkeypatch):
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
                "https_proxy", "http_proxy", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(key, raising=False)

    _create_openai_client(
        api_key="test-key",
        base_url="https://litellm.internal.example.com/v1",
    )

    http_client = mock_openai.call_args.kwargs.get("http_client")
    assert isinstance(http_client, httpx.Client)
    assert "HTTPProxy" not in _pool_types(http_client)
    http_client.close()


@patch("agent.auxiliary_client.OpenAI")
def test_create_openai_client_ignores_macos_system_proxy(mock_openai, monkeypatch):
    """System proxy from getproxies() must not apply when env vars are unset."""
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
                "https_proxy", "http_proxy", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(key, raising=False)

    with patch(
        "urllib.request.getproxies",
        return_value={"http": "http://127.0.0.1:7897", "https": "http://127.0.0.1:7897"},
    ):
        _create_openai_client(
            api_key="test-key",
            base_url="https://litellm.internal.example.com/v1",
        )

    http_client = mock_openai.call_args.kwargs.get("http_client")
    assert isinstance(http_client, httpx.Client)
    assert "HTTPProxy" not in _pool_types(http_client)
    http_client.close()


def test_get_proxy_for_base_url_respects_no_proxy(monkeypatch):
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
                "https_proxy", "http_proxy", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:7897")
    monkeypatch.setenv("NO_PROXY", "internal.example.com")

    assert _get_proxy_for_base_url("https://litellm.internal.example.com/v1") is None
    assert _get_proxy_for_base_url("https://api.openai.com/v1") == "http://127.0.0.1:7897"


def test_openai_http_client_kwargs_async_mode():
    kwargs = _openai_http_client_kwargs(
        "https://litellm.internal.example.com/v1",
        async_mode=True,
    )
    assert isinstance(kwargs["http_client"], httpx.AsyncClient)
