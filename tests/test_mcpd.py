"""The MCP gateway: what it will build an argv for, and what it refuses."""

from __future__ import annotations

import json
import os
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from clixz import mcpd
from clixz.mcpd import (
    APPLIED_ACTIONS,
    NAMED_PLAN_ACTIONS,
    READ_COMMANDS,
    RELAYED,
    RequestError,
    access,
    build_argv,
    handle,
    route,
)


class ReadTests(unittest.TestCase):
    def test_every_read_command_builds(self) -> None:
        for cmd in READ_COMMANDS:
            request = {"cmd": cmd}
            if cmd == "show":
                request["service"] = "apps/atuin"
            if cmd == "todo-show":
                request["id"] = 1
            self.assertIn("--json", build_argv(request))

    def test_check_accepts_an_optional_service(self) -> None:
        self.assertIn("apps/atuin", build_argv({"cmd": "check", "service": "apps/atuin"}))
        self.assertNotIn("apps/atuin", build_argv({"cmd": "check"}))

    def test_check_verbose_is_a_flag_not_a_value(self) -> None:
        self.assertIn("--verbose", build_argv({"cmd": "check", "verbose": True}))
        self.assertNotIn("--verbose", build_argv({"cmd": "check", "verbose": "--config x"}))
        self.assertNotIn("--verbose", build_argv({"cmd": "show", "service": "apps/x",
                                                  "verbose": True}))

    def test_manifest_is_always_a_dry_run(self) -> None:
        self.assertIn("--dry-run", build_argv({"cmd": "manifest"}))


class RelayRoutingTests(unittest.TestCase):
    """Plans for services, applies and todo writes go to clixz-apply."""

    def test_every_applied_action_is_relayed_with_its_files(self) -> None:
        for action in APPLIED_ACTIONS:
            request = {"cmd": "plan", "action": action, "service": "apps/x"}
            if action in ("new", "edit"):
                request |= {"compose": "services: {}\n", "service_yaml": "name: x\n"}
            kind, payload = route(request)
            self.assertEqual("relay", kind, action)
            self.assertEqual(request, payload)

    def test_a_mutating_verb_cannot_be_called_directly(self) -> None:
        for action in APPLIED_ACTIONS:
            with self.assertRaises(RequestError):
                route({"cmd": action, "service": "apps/x"})

    def test_only_known_fields_are_relayed(self) -> None:
        _, payload = route({"cmd": "plan", "action": "rm", "service": "apps/x", "force": True,
                            "argv": ["rm", "-rf", "/"]})
        self.assertEqual({"cmd": "plan", "action": "rm", "service": "apps/x"}, payload)

    def test_stack_only_with_new(self) -> None:
        self.assertEqual("demo", route({"cmd": "plan", "action": "new", "service": "apps/x",
                                        "stack": "demo"})[1]["stack"])
        with self.assertRaises(RequestError):
            route({"cmd": "plan", "action": "edit", "service": "apps/x", "stack": "demo"})

    def test_relayed_fields_are_checked_here_too(self) -> None:
        bad = (
            {"cmd": "plan", "action": "new", "service": "apps/x; id"},
            {"cmd": "plan", "action": "new", "service": "apps/x", "compose": 3},
            {"cmd": "plan", "action": "new", "service": "apps/x", "compose": "x" * (128 * 1024 + 1)},
            {"cmd": "plan", "action": "edit"},
            {"cmd": "apply"},
            {"cmd": "apply", "plan_id": "../../etc"},
            {"cmd": "plan-drop", "plan_id": 12345678},
            {"cmd": "todo-add"},
            {"cmd": "todo-add", "title": ["x"]},
            {"cmd": "todo-edit", "id": True, "state": "done"},
            {"cmd": "todo-rm", "id": "1"},
        )
        for request in bad:
            with self.assertRaises(RequestError, msg=request):
                route(request)

    def test_relayed_reads_and_writes(self) -> None:
        for request in ({"cmd": "plans"}, {"cmd": "exposed"},
                        {"cmd": "apply", "plan_id": "0a1b2c3d"},
                        {"cmd": "plan-show", "plan_id": "0a1b2c3d"},
                        {"cmd": "plan-drop", "plan_id": "0a1b2c3d"},
                        {"cmd": "todo-add", "title": "t", "description": "d"},
                        {"cmd": "todo-edit", "id": 3, "state": "done"},
                        {"cmd": "todo-rm", "id": 3}):
            self.assertEqual(("relay", request), route(request))
        self.assertEqual(set(RELAYED), {"plans", "exposed", "apply", "plan-show", "plan-drop",
                                        "todo-add", "todo-edit", "todo-rm"})

    def test_the_todo_is_read_through_the_cli(self) -> None:
        self.assertEqual(["todo", "ls", "--all", "--json"], build_argv({"cmd": "todo"})[1:])
        self.assertEqual(["todo", "ls", "--state", "doing", "--json"],
                         build_argv({"cmd": "todo", "state": "doing"})[1:])
        self.assertEqual(["todo", "show", "4", "--json"],
                         build_argv({"cmd": "todo-show", "id": 4})[1:])
        for bad in ({"cmd": "todo", "state": "--all; id"}, {"cmd": "todo-show", "id": "4"}):
            with self.assertRaises(RequestError, msg=bad):
                build_argv(bad)

    def test_the_gateway_reports_its_own_version(self) -> None:
        kind, answer = route({"cmd": "version"})
        self.assertEqual("local", kind)
        self.assertEqual(mcpd.__version__, answer["version"])


class RelaySocketTests(unittest.TestCase):
    def test_a_missing_applier_says_how_to_install_it(self) -> None:
        with mock.patch.object(mcpd, "APPLY_SOCKET", "/nonexistent/clixz-apply.sock"):
            answer = handle(b'{"cmd": "plans"}')
        self.assertFalse(answer["ok"])
        self.assertIn("clixz daemon install", answer["error"])

    def test_the_request_goes_out_and_the_answer_comes_back(self) -> None:
        received = []

        class Echo(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                request = json.loads(self.rfile.readline())
                received.append(request)
                self.wfile.write(json.dumps({"ok": True, "plans": []}).encode() + b"\n")

        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "apply.sock")
            server = socketserver.UnixStreamServer(path, Echo)
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()
            with mock.patch.object(mcpd, "APPLY_SOCKET", path):
                answer = handle(b'{"cmd": "plans", "extra": "dropped"}')
            thread.join(5)
            server.server_close()
        self.assertEqual({"ok": True, "plans": []}, answer)
        self.assertEqual([{"cmd": "plans"}], received)


class VersionTests(unittest.TestCase):
    def test_a_changed_install_is_noticed(self) -> None:
        with mock.patch.object(mcpd, "installed_version", return_value="99.0.0"):
            self.assertTrue(mcpd.version_changed())
        with mock.patch.object(mcpd, "installed_version", return_value=mcpd.__version__):
            self.assertFalse(mcpd.version_changed())

    def test_an_unknown_install_is_not_a_reason_to_exit(self) -> None:
        with mock.patch.object(mcpd, "installed_version", return_value=None):
            self.assertFalse(mcpd.version_changed())

    def test_the_server_shuts_down_when_the_version_changed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = mcpd.Server(os.path.join(tmp, "s.sock"), mcpd.Handler)
            server.check_interval = 0
            with mock.patch.object(mcpd, "installed_version", return_value="99.0.0"):
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
                thread.start()
                thread.join(5)
            server.server_close()
        self.assertFalse(thread.is_alive())


class NamedPlanTests(unittest.TestCase):
    def test_a_category_is_only_ever_planned(self) -> None:
        argv = build_argv({"cmd": "plan", "action": "category-add", "name": "media"})
        self.assertEqual(["category", "add", "media", "--plan", "--json"], argv[1:])

    def test_a_repo_is_only_ever_planned(self) -> None:
        argv = build_argv({"cmd": "plan", "action": "repo-add", "name": "demo",
                           "url": "https://github.com/me/demo.git"})
        self.assertEqual(["repo", "add", "demo", "--url", "https://github.com/me/demo.git",
                          "--plan", "--json"], argv[1:])
        argv = build_argv({"cmd": "plan", "action": "repo-rm", "name": "demo"})
        self.assertEqual(["repo", "rm", "demo", "--plan", "--json"], argv[1:])

    def test_the_group_verbs_are_not_reachable_directly(self) -> None:
        for cmd in ("category", "repo", "category add", "repo-add", "category-add"):
            with self.assertRaises(RequestError, msg=cmd):
                build_argv({"cmd": cmd, "name": "media"})

    def test_listings_take_no_argument(self) -> None:
        self.assertEqual(["repo", "ls", "--json"],
                         build_argv({"cmd": "repos", "name": "--help"})[1:])
        self.assertEqual(["category", "ls", "--json"], build_argv({"cmd": "categories"})[1:])

    def test_names_urls_and_accounts_are_validated(self) -> None:
        bad = (
            {"action": "category-add", "name": "../etc"},
            {"action": "category-add", "name": "--yes"},
            {"action": "category-add", "name": "media", "account": "root; id"},
            {"action": "category-add"},
            {"action": "repo-add", "name": "a/b"},
            {"action": "repo-add", "name": "demo", "url": "--upload-pack=id"},
            {"action": "repo-add", "name": "demo", "url": "file:///etc/shadow"},
            {"action": "repo-add", "name": "demo", "url": 42},
            {"action": "repo-rm", "name": ".."},
        )
        for request in bad:
            with self.assertRaises(RequestError, msg=request):
                build_argv({"cmd": "plan", **request})


class AccessTests(unittest.TestCase):
    def test_every_verb_the_daemon_accepts_is_listed(self) -> None:
        listed = access()
        self.assertEqual(list(READ_COMMANDS), [r["request"] for r in listed["read"]])
        self.assertEqual(list(NAMED_PLAN_ACTIONS), [r["request"] for r in listed["plan"]])
        self.assertEqual([f"plan {a}" for a in APPLIED_ACTIONS] + list(RELAYED),
                         [r["request"] for r in listed["relay"]])

    def test_named_mutations_are_only_ever_planned(self) -> None:
        for row in access()["plan"]:
            self.assertIn("--plan", row["runs"], row)


class ValidationTests(unittest.TestCase):
    def test_shell_metacharacters_are_refused(self) -> None:
        for bad in ("a; rm -rf /", "a b", "../etc", "a|b", "-rf", ""):
            with self.assertRaises(RequestError, msg=bad):
                build_argv({"cmd": "show", "service": bad})

    def test_a_non_string_service_is_refused_not_coerced(self) -> None:
        # str(42) satisfies the regex; accepting it would let a caller smuggle
        # a value through a type the validator never looked at.
        with self.assertRaises(RequestError):
            build_argv({"cmd": "show", "service": 42})

    def test_bad_category_is_refused(self) -> None:
        with self.assertRaises(RequestError):
            build_argv({"cmd": "ls", "category": "apps; id"})

    def test_unknown_command_is_refused(self) -> None:
        with self.assertRaises(RequestError):
            build_argv({"cmd": "exec"})

    def test_no_extra_option_can_be_smuggled_through_a_request_field(self) -> None:
        argv = build_argv({"cmd": "ls", "extra": "--config /tmp/evil.yaml",
                           "config": "/tmp/evil.yaml"})
        self.assertEqual(["ls", "--json"], argv[1:])


class HandleTests(unittest.TestCase):
    def test_malformed_json_answers_an_error(self) -> None:
        self.assertFalse(handle(b"{not json")["ok"])

    def test_non_object_answers_an_error(self) -> None:
        self.assertFalse(handle(b"[1,2]")["ok"])

    def test_refusal_message_reaches_the_caller(self) -> None:
        self.assertIn("not allowed", handle(b'{"cmd":"exec"}')["error"])
