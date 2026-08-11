"""COM-8386: _broken expires; reaper skips in-use clients."""
from __future__ import annotations

import asyncio
import time
import types
import unittest
from unittest import mock

# Minimal stand-in so we can exercise the latch helpers without full LSP.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.lsp import manager as mgr


class DummyClient:
    def __init__(self, sid="pyright", root="/tmp/ws"):
        self.server_id = sid
        self.workspace_root = root
        self.is_running = True
        self.state = "running"
        self.shutdown_calls = 0

    async def shutdown(self):
        self.shutdown_calls += 1
        self.is_running = False


class BrokenExpiryTests(unittest.TestCase):
    def _svc(self):
        # Build without starting the real background loop / reaper.
        with mock.patch.object(mgr.LSPService, "__init__", lambda self, *a, **k: None):
            s = mgr.LSPService()  # type: ignore
        s._enabled = True
        s._idle_timeout = 1.0
        s._broken_ttl = 0.05
        s._broken = {}
        s._clients = {}
        s._spawning = {}
        s._last_used = {}
        s._in_use = {}
        s._state_lock = __import__("threading").Lock()
        s._reaper_interval = 0.05
        return s

    def test_broken_expires(self):
        s = self._svc()
        key = ("pyright", "/tmp/ws")
        s._mark_broken_key(key)
        self.assertTrue(s._is_broken(key))
        time.sleep(0.06)
        self.assertFalse(s._is_broken(key))
        self.assertNotIn(key, s._broken)

    def test_reap_skips_in_use(self):
        s = self._svc()
        key = ("pyright", "/tmp/ws")
        c = DummyClient()
        s._clients[key] = c
        s._last_used[key] = time.time() - 100  # idle long enough
        s._in_use[key] = 1
        asyncio.run(s._reap_idle_once())
        self.assertIn(key, s._clients)
        self.assertEqual(c.shutdown_calls, 0)

    def test_reap_idle_when_not_in_use(self):
        s = self._svc()
        key = ("pyright", "/tmp/ws")
        c = DummyClient()
        s._clients[key] = c
        s._last_used[key] = time.time() - 100
        asyncio.run(s._reap_idle_once())
        self.assertNotIn(key, s._clients)
        self.assertEqual(c.shutdown_calls, 1)


if __name__ == "__main__":
    unittest.main()
