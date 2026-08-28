"""Tests for the unprivileged gateway.

Its job is to be narrow: a closed allowlist for read-only commands, strict
argument checking, and no ability to mutate anything itself.
"""

from __future__ import annotations

import unittest
from unittest import mock

from clixz import runnerd


class AllowlistTests(unittest.TestCase):
    def test_only_check_and_list_are_executed(self) -> None:
        self.assertEqual(runnerd._build_argv({"cmd": "check"})[1:], ["check"])
        self.assertEqual(runnerd._build_argv({"cmd": "list"})[1:], ["list"])

    def test_mutating_commands_are_not_executed_here(self) -> None:
        for cmd in ("apply", "create", "update", "archive", "dev", "edit", "meta", "image"):
            with self.subTest(cmd=cmd):
                with self.assertRaises(ValueError):
                    runnerd._build_argv({"cmd": cmd})

    def test_rejects_injected_arguments(self) -> None:
        for service in ("a; rm -rf /", "../../etc", "-v --help", "a b", "$(id)", "a|b"):
            with self.subTest(service=service):
                with self.assertRaises(ValueError):
                    runnerd._build_argv({"cmd": "check", "service": service})

    def test_rejects_injected_category(self) -> None:
        for category in ("a|b", "../etc", "a b", ""):
            with self.subTest(category=category):
                if category == "":
                    # Falsy: treated as "no filter", which is legitimate.
                    self.assertEqual(runnerd._build_argv({"cmd": "list", "category": ""})[1:],
                                     ["list"])
                    continue
                with self.assertRaises(ValueError):
                    runnerd._build_argv({"cmd": "list", "category": category})

    def test_rejects_non_string_service(self) -> None:
        for service in ({"$ne": 1}, ["a"], 42):
            with self.subTest(service=service):
                with self.assertRaises(ValueError):
                    runnerd._build_argv({"cmd": "check", "service": service})

    def test_accepts_a_qualified_service_name(self) -> None:
        argv = runnerd._build_argv({"cmd": "check", "service": "apps/bitwarden"})
        self.assertEqual(argv[1:], ["check", "apps/bitwarden"])


class RelayTests(unittest.TestCase):
    def test_relay_is_declared_for_mutations_only(self) -> None:
        self.assertEqual(set(runnerd.RELAYED), {"plan", "apply"})

    def test_relay_reports_a_missing_daemon_clearly(self) -> None:
        with mock.patch.object(runnerd, "ADMIN_SOCKET", "/nonexistent/admin.sock"):
            resp = runnerd._relay({"cmd": "plan", "action": "update", "service": "x"})
        self.assertFalse(resp["ok"])
        self.assertIn("clixz-admind", resp["error"])

    def test_relay_renames_cmd_to_op(self) -> None:
        captured: dict = {}

        class FakeSock:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def settimeout(self, _): pass
            def connect(self, _): pass
            def sendall(self, data): captured["payload"] = data
            def recv(self, _): return b'{"ok": true}\n'

        with mock.patch.object(runnerd.socket, "socket", lambda *a, **k: FakeSock()):
            runnerd._relay({"cmd": "plan", "action": "archive", "service": "demo"})

        import json
        sent = json.loads(captured["payload"].decode())
        self.assertEqual(sent["op"], "plan")
        self.assertNotIn("cmd", sent)
        self.assertEqual(sent["action"], "archive")


class EnvironmentTests(unittest.TestCase):
    def test_subprocess_env_disables_sudo_escalation(self) -> None:
        # Without CLIXZ_NO_SUDO, ensure_root() would try to re-exec via sudo.
        captured: dict = {}

        def fake_run(argv, **kwargs):
            captured.update(kwargs)
            raise OSError("stop here")

        with mock.patch.object(runnerd.subprocess, "run", fake_run):
            runnerd._run(["/bin/true", "check"])
        self.assertEqual(captured["env"]["CLIXZ_NO_SUDO"], "1")
        self.assertFalse(captured["shell"])


if __name__ == "__main__":
    unittest.main()
