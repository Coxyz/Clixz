"""The MCP gateway: what it will build an argv for, and what it refuses."""

from __future__ import annotations

import unittest

from clixz.mcpd import PLAN_ACTIONS, READ_COMMANDS, RequestError, build_argv, handle


class ReadTests(unittest.TestCase):
    def test_every_read_command_builds(self) -> None:
        for cmd in READ_COMMANDS:
            request = {"cmd": cmd}
            if cmd == "show":
                request["service"] = "apps/atuin"
            self.assertIn("--json", build_argv(request))

    def test_check_accepts_an_optional_service(self) -> None:
        self.assertIn("apps/atuin", build_argv({"cmd": "check", "service": "apps/atuin"}))
        self.assertNotIn("apps/atuin", build_argv({"cmd": "check"}))

    def test_manifest_is_always_a_dry_run(self) -> None:
        self.assertIn("--dry-run", build_argv({"cmd": "manifest"}))


class MutationTests(unittest.TestCase):
    def test_every_mutating_action_is_forced_to_plan(self) -> None:
        for action in PLAN_ACTIONS:
            argv = build_argv({"cmd": "plan", "action": action, "service": "apps/x"})
            self.assertIn("--plan", argv)

    def test_a_mutating_verb_cannot_be_called_directly(self) -> None:
        for action in PLAN_ACTIONS:
            with self.assertRaises(RequestError):
                build_argv({"cmd": action, "service": "apps/x"})

    def test_force_is_not_expressible(self) -> None:
        argv = build_argv({"cmd": "plan", "action": "rm", "service": "apps/x",
                           "force": True})
        self.assertNotIn("--force", argv)

    def test_unknown_action_is_refused(self) -> None:
        with self.assertRaises(RequestError):
            build_argv({"cmd": "plan", "action": "destroy", "service": "apps/x"})


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
