"""clixz-apply: the root process started for one request from clixz-mcpd."""

from __future__ import annotations

import grp
import json
import os
import pwd
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clixz.applyd import MAX_REQUEST, handle
from clixz.config import parse_config

COMPOSE = "services:\n  demo:\n    image: nginx:1.27\n"


def _send(config, payload) -> dict:
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    return handle(raw, config)


class ApplydTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.root = base / "tree"
        self.root.mkdir()
        user = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("CLIXZ_STATE_DIR", None)
        self.config = parse_config({
            "root_dir": str(self.root),
            "categories": {"apps": {"user": user, "group": group}},
            "rules": {"env": {"mode": "600", "owner": f"{user}:{group}"}},
            "api": {"manifest": str(base / "manifest.json")},
            "state": {"dir": str(base / "state")},
            "npm": {"database": None},
        })

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_malformed_requests_are_answered_not_raised(self) -> None:
        for raw in (b"not json", b"[1, 2]", b"\xff\xfe", json.dumps({"cmd": "rm -rf"}).encode()):
            answer = _send(self.config, raw)
            self.assertFalse(answer["ok"], raw)
            self.assertTrue(answer["error"])

    def test_an_oversized_request_is_refused(self) -> None:
        answer = _send(self.config, b"x" * (MAX_REQUEST + 1))
        self.assertFalse(answer["ok"])

    def test_a_blocked_plan_is_answered_with_its_reasons_and_no_id(self) -> None:
        answer = _send(self.config, {"cmd": "plan", "action": "new", "service": "apps/demo",
                                     "compose": "services:\n  demo:\n    privileged: true\n"})
        self.assertTrue(answer["ok"])
        self.assertIsNone(answer["plan"]["id"])
        self.assertTrue(answer["plan"]["blocked"])
        self.assertEqual([], _send(self.config, {"cmd": "plans"})["plans"])

    def test_plan_then_apply(self) -> None:
        planned = _send(self.config, {"cmd": "plan", "action": "new", "service": "apps/demo",
                                      "compose": COMPOSE})
        self.assertTrue(planned["ok"], planned)
        plan_id = planned["plan"]["id"]
        self.assertEqual("mcp", planned["plan"]["origin"])
        self.assertEqual([plan_id], [p["id"] for p in _send(self.config, {"cmd": "plans"})["plans"]])
        self.assertEqual(COMPOSE, _send(self.config, {"cmd": "plan-show", "plan_id": plan_id})
                         ["plan"]["request"]["compose"])
        applied = _send(self.config, {"cmd": "apply", "plan_id": plan_id})
        self.assertTrue(applied["ok"], applied)
        self.assertTrue((self.root / "apps" / "demo" / "compose.yaml").is_file())
        again = _send(self.config, {"cmd": "apply", "plan_id": plan_id})
        self.assertFalse(again["ok"])

    def test_plan_drop(self) -> None:
        plan_id = _send(self.config, {"cmd": "plan", "action": "new",
                                      "service": "apps/demo"})["plan"]["id"]
        dropped = _send(self.config, {"cmd": "plan-drop", "plan_id": plan_id})
        self.assertTrue(dropped["ok"])
        self.assertEqual([], _send(self.config, {"cmd": "plans"})["plans"])

    def test_a_bad_plan_id_is_refused(self) -> None:
        for cmd in ("apply", "plan-show", "plan-drop"):
            for plan_id in ("../x", 12345678, None):
                answer = _send(self.config, {"cmd": cmd, "plan_id": plan_id})
                self.assertFalse(answer["ok"], (cmd, plan_id))

    def test_force_cannot_be_smuggled_into_rm(self) -> None:
        (self.root / "apps" / "demo").mkdir(parents=True)
        answer = _send(self.config, {"cmd": "plan", "action": "rm", "service": "apps/demo",
                                     "force": True})
        self.assertTrue(answer["ok"])
        self.assertEqual("mv", answer["plan"]["commands"][0][0])

    def test_todo_writes(self) -> None:
        added = _send(self.config, {"cmd": "todo-add", "title": "Backups", "description": "restic",
                                    "id": 99})
        self.assertTrue(added["ok"], added)
        self.assertEqual(1, added["item"]["id"])
        edited = _send(self.config, {"cmd": "todo-edit", "id": 1, "state": "doing"})
        self.assertEqual("doing", edited["item"]["state"])
        removed = _send(self.config, {"cmd": "todo-rm", "id": 1})
        self.assertEqual("Backups", removed["removed"]["title"])

    def test_todo_types_are_checked(self) -> None:
        for payload in ({"cmd": "todo-add", "title": 3},
                        {"cmd": "todo-edit", "id": "1", "state": "done"},
                        {"cmd": "todo-edit", "id": True, "state": "done"},
                        {"cmd": "todo-rm", "id": 7}):
            self.assertFalse(_send(self.config, payload)["ok"], payload)

    def test_an_unexpected_error_still_gets_an_answer(self) -> None:
        with mock.patch("clixz.applyd.exposure_payload", side_effect=KeyError("boom")):
            answer = _send(self.config, {"cmd": "exposed"})
        self.assertFalse(answer["ok"])
        self.assertIn("boom", answer["error"])

    def test_exposed_answers_even_without_a_database(self) -> None:
        answer = _send(self.config, {"cmd": "exposed"})
        self.assertTrue(answer["ok"])
        self.assertFalse(answer["available"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
