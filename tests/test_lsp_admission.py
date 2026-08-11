"""COM-8387: simultaneous-cardinality admission control."""
from __future__ import annotations

import asyncio
import time
import unittest
from unittest import mock
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.lsp import manager as mgr


class DummyClient:
    def __init__(self, sid="typescript", root="/tmp/a", rss=0):
        self.server_id = sid
        self.workspace_root = root
        self.is_running = True
        self.state = "running"
        self.shutdown_calls = 0
        self._rss = rss
        self._proc = mock.Mock(pid=None)

    async def shutdown(self):
        self.shutdown_calls += 1
        self.is_running = False


class AdmissionTests(unittest.TestCase):
    def _svc(self, max_clients=2, budget=10_000):
        with mock.patch.object(mgr.LSPService, "__init__", lambda self, *a, **k: None):
            s = mgr.LSPService()  # type: ignore
        s._enabled = True
        s._idle_timeout = 600
        s._max_clients = max_clients
        s._memory_budget_bytes = budget
        s._broken = {}
        s._broken_ttl = 120
        s._clients = {}
        s._spawning = {}
        s._last_used = {}
        s._in_use = {}
        s._state_lock = __import__("threading").Lock()
        # RSS stub: use DummyClient._rss via patched method
        s._client_rss_bytes = lambda c: getattr(c, "_rss", 0)
        return s

    def test_admit_when_under_budget(self):
        s = self._svc(max_clients=2, budget=10_000)
        ok = asyncio.run(s._admit_for_spawn(("typescript", "/tmp/new")))
        self.assertTrue(ok)

    def test_evict_lru_idle_to_make_room(self):
        s = self._svc(max_clients=2, budget=10_000)
        a = DummyClient("typescript", "/tmp/a")
        b = DummyClient("typescript", "/tmp/b")
        s._clients[("typescript", "/tmp/a")] = a
        s._clients[("typescript", "/tmp/b")] = b
        s._last_used[("typescript", "/tmp/a")] = time.time() - 1000
        s._last_used[("typescript", "/tmp/b")] = time.time() - 10
        ok = asyncio.run(s._admit_for_spawn(("typescript", "/tmp/c")))
        self.assertTrue(ok)
        self.assertNotIn(("typescript", "/tmp/a"), s._clients)
        self.assertIn(("typescript", "/tmp/b"), s._clients)
        self.assertEqual(a.shutdown_calls, 1)
        self.assertEqual(b.shutdown_calls, 0)

    def test_deny_when_all_in_use(self):
        s = self._svc(max_clients=2, budget=10_000)
        a = DummyClient("typescript", "/tmp/a")
        b = DummyClient("typescript", "/tmp/b")
        s._clients[("typescript", "/tmp/a")] = a
        s._clients[("typescript", "/tmp/b")] = b
        s._last_used[("typescript", "/tmp/a")] = time.time() - 1000
        s._last_used[("typescript", "/tmp/b")] = time.time() - 1000
        s._in_use[("typescript", "/tmp/a")] = 1
        s._in_use[("typescript", "/tmp/b")] = 1
        ok = asyncio.run(s._admit_for_spawn(("typescript", "/tmp/c")))
        self.assertFalse(ok)
        self.assertEqual(len(s._clients), 2)
        self.assertEqual(a.shutdown_calls, 0)

    def test_memory_budget_triggers_evict(self):
        s = self._svc(max_clients=0, budget=1000)  # unlimited count, tight memory
        a = DummyClient("typescript", "/tmp/a", rss=1500)
        s._clients[("typescript", "/tmp/a")] = a
        s._last_used[("typescript", "/tmp/a")] = time.time() - 100
        ok = asyncio.run(s._admit_for_spawn(("typescript", "/tmp/b")))
        self.assertTrue(ok)
        self.assertNotIn(("typescript", "/tmp/a"), s._clients)
        self.assertEqual(a.shutdown_calls, 1)


if __name__ == "__main__":
    unittest.main()
